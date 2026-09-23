#!/usr/bin/env python3
"""Real local journal I/O and supplemental witness source-linkage controls.

The production guard-free helper operates on tiny real TemporaryDirectory
files and directory descriptors. Successful writes, chmod, fsync and Linux
renameat2(RENAME_NOREPLACE) are real; selected syscalls alone inject failures.
Reopen callbacks validate fixture bytes/mode, not witness signatures, launch
authority, external high-water, storage survival or physical crash recovery.
The guarded witness is inspected as source, never imported or bypassed. These
tests do not prove its deployed replay, signer, concurrency or service behavior.
"""
from __future__ import annotations

import ast
import errno
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_witness_journal as journal


RECORD = b'{"kind":"fixture","stateSequence":1}\n'
TEMPORARY = ".tmp-fixture-1"
PUBLISHED = "record-fixture-1.json"


class WitnessJournalIOTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="witness-journal-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        os.chmod(self.path, 0o700)
        self.descriptor = os.open(
            self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        self.addCleanup(os.close, self.descriptor)
        self.handle = self.new_handle()

    def new_handle(self):
        return journal.WitnessJournalIO(self.descriptor, maximum_record_bytes=1024)

    def stamp(self):
        metadata = os.fstat(self.descriptor)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def recover(self, handle=None):
        current = self.handle if handle is None else handle

        def scan():
            self.assertEqual(os.listdir(self.descriptor), [])
            return self.stamp()

        self.assertEqual(current.recover(scan), self.stamp())
        return current

    def assert_poisoned(self, handle=None):
        current = self.handle if handle is None else handle
        with self.assertRaises(journal.JournalError):
            current.require_ready()
        with self.assertRaises(journal.JournalError):
            with current.ready():
                self.fail("poisoned journal released its ready context")
        with self.assertRaises(journal.JournalError):
            current.publish(".tmp-later", "record-later.json", RECORD)
        with self.assertRaises(journal.JournalError):
            current.recover(lambda: self.fail("poisoned journal reran recovery"))

    def assert_record(self, expected=RECORD, name=PUBLISHED):
        metadata = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertEqual((self.path / name).read_bytes(), expected)

    def test_unrecovered_handle_denies_publication_and_ready_context(self):
        with self.assertRaises(journal.JournalError):
            self.handle.require_ready()
        with self.assertRaises(journal.JournalError):
            self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        with self.assertRaises(journal.JournalError):
            with self.handle.ready():
                self.fail("unrecovered journal became ready")
        self.assertEqual(os.listdir(self.descriptor), [])
        self.recover()
        self.handle.require_ready()
        with self.handle.ready():
            self.handle.require_ready()

    def test_recovery_always_syncs_directory_after_validated_scan_once(self):
        events = []
        real_fsync = os.fsync

        def scan():
            self.assertEqual(os.listdir(self.descriptor), [])
            events.append("scan")
            return self.stamp()

        def fsync(descriptor):
            self.assertEqual(descriptor, self.descriptor)
            events.append("directory-fsync")
            real_fsync(descriptor)

        with mock.patch.object(journal.os, "fsync", side_effect=fsync):
            self.handle.recover(scan)
        self.assertEqual(events, ["scan", "directory-fsync"])
        self.handle.require_ready()
        with self.assertRaises(journal.JournalError):
            self.handle.recover(lambda: self.fail("repeated recovery was invoked"))

    def test_successful_publication_uses_real_file_rename_directory_order(self):
        self.recover()
        events = []
        real_fsync, real_rename = os.fsync, journal._rename_noreplace

        def fsync(descriptor):
            mode = os.fstat(descriptor).st_mode
            if stat.S_ISREG(mode):
                self.assertEqual(stat.S_IMODE(mode), 0o400)
                self.assertFalse((self.path / PUBLISHED).exists())
                events.append("file-fsync")
            else:
                self.assertEqual(descriptor, self.descriptor)
                self.assert_record()
                events.append("directory-fsync")
            real_fsync(descriptor)

        def rename(descriptor, temporary, published):
            self.assertEqual((descriptor, temporary, published),
                             (self.descriptor, TEMPORARY, PUBLISHED))
            events.append("rename-noreplace")
            real_rename(descriptor, temporary, published)

        with mock.patch.object(journal.os, "fsync", side_effect=fsync), \
                mock.patch.object(journal, "_rename_noreplace", side_effect=rename):
            self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertEqual(events, ["file-fsync", "rename-noreplace", "directory-fsync"])
        self.assertEqual(os.listdir(self.descriptor), [PUBLISHED])
        self.assert_record()
        self.handle.require_ready()
        # The production helper borrows, rather than closes, its directory FD.
        self.assertTrue(stat.S_ISDIR(os.fstat(self.descriptor).st_mode))

    def test_partial_real_writes_complete_the_exact_record(self):
        self.recover()
        real_write = os.write
        writes = []

        def partial(descriptor, data):
            written = real_write(descriptor, data[:3])
            writes.append(written)
            return written

        with mock.patch.object(journal.os, "write", side_effect=partial):
            self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertGreater(len(writes), 1)
        self.assertEqual(sum(writes), len(RECORD))
        self.assert_record()

    def test_zero_progress_write_cleans_temporary_and_poison_is_sticky(self):
        self.recover()
        with mock.patch.object(journal.os, "write", return_value=0):
            with self.assertRaises(journal.JournalError):
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertEqual(os.listdir(self.descriptor), [])
        self.assert_poisoned()
        fresh = self.recover(self.new_handle())
        fresh.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assert_record()

    def test_error_after_partial_write_cleans_temporary_without_publication(self):
        self.recover()
        failure = OSError(errno.EIO, "injected write failure")
        real_write = os.write
        calls = []

        def partial_then_error(descriptor, data):
            calls.append(len(data))
            if len(calls) == 1:
                return real_write(descriptor, data[:4])
            raise failure

        with mock.patch.object(journal.os, "write", side_effect=partial_then_error):
            with self.assertRaises(OSError) as raised:
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertIs(raised.exception, failure)
        self.assertEqual(len(calls), 2)
        self.assertEqual(os.listdir(self.descriptor), [])
        self.assert_poisoned()

    def test_file_fsync_failure_prevents_rename_and_cleans_temporary(self):
        self.recover()
        real_fsync = os.fsync
        failure = OSError(errno.EIO, "injected file fsync failure")
        events = []

        def fsync(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                events.append("file-failed")
                raise failure
            events.append("cleanup-directory-fsync")
            real_fsync(descriptor)

        with mock.patch.object(journal.os, "fsync", side_effect=fsync), \
                mock.patch.object(journal, "_rename_noreplace", side_effect=AssertionError("rename preceded file fsync")):
            with self.assertRaises(OSError) as raised:
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertIs(raised.exception, failure)
        self.assertEqual(events, ["file-failed", "cleanup-directory-fsync"])
        self.assertEqual(os.listdir(self.descriptor), [])
        self.assert_poisoned()

    def test_rename_failure_cleans_temporary_without_publishing(self):
        self.recover()
        failure = OSError(errno.EIO, "injected rename failure")
        with mock.patch.object(journal, "_rename_noreplace", side_effect=failure):
            with self.assertRaises(OSError) as raised:
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertIs(raised.exception, failure)
        self.assertEqual(os.listdir(self.descriptor), [])
        self.assert_poisoned()

    def test_postrename_directory_failure_retains_record_but_denies_all_reuse(self):
        self.recover()
        real_fsync = os.fsync
        failure = OSError(errno.EIO, "injected directory fsync failure")

        def fsync(descriptor):
            if descriptor == self.descriptor:
                self.assert_record()
                raise failure
            real_fsync(descriptor)

        with mock.patch.object(journal.os, "fsync", side_effect=fsync):
            with self.assertRaises(OSError) as raised:
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertIs(raised.exception, failure)
        self.assertEqual(os.listdir(self.descriptor), [PUBLISHED])
        self.assert_record()
        self.assert_poisoned()

        # Fresh I/O handle, not same-handle retry: validate retained bytes then
        # perform a real directory barrier before the new ready context opens.
        events = []
        fresh = self.new_handle()

        def scan():
            self.assert_record()
            events.append("validated-retained-record")
            return self.stamp()

        def repaired_fsync(descriptor):
            self.assertEqual(descriptor, self.descriptor)
            events.append("repaired-directory-fsync")
            real_fsync(descriptor)

        with mock.patch.object(journal.os, "fsync", side_effect=repaired_fsync):
            fresh.recover(scan)
        with fresh.ready():
            events.append("ready")
            self.assert_record()
        self.assertEqual(events, ["validated-retained-record", "repaired-directory-fsync", "ready"])
        self.assert_poisoned()

    def test_reopen_directory_barrier_failure_never_releases_ready_state(self):
        self.recover()
        self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        fresh = self.new_handle()
        failure = OSError(errno.EIO, "injected reopen fsync failure")

        def scan():
            self.assert_record()
            return self.stamp()

        with mock.patch.object(journal.os, "fsync", side_effect=failure):
            with self.assertRaises(OSError) as raised:
                fresh.recover(scan)
        self.assertIs(raised.exception, failure)
        self.assert_record()
        self.assert_poisoned(fresh)

    def test_failed_scan_never_executes_barrier_or_accepts_a_record(self):
        failure = ValueError("fixture scan rejected its record")

        def reject():
            raise failure

        with mock.patch.object(journal.os, "fsync", side_effect=AssertionError("barrier followed rejected scan")):
            with self.assertRaises(ValueError) as raised:
                self.handle.recover(reject)
        self.assertIs(raised.exception, failure)
        self.assert_poisoned()

    def test_real_noreplace_conflict_never_overwrites_existing_record(self):
        self.recover()
        self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        original = os.stat(PUBLISHED, dir_fd=self.descriptor, follow_symlinks=False)
        with self.assertRaises(journal.JournalConflict):
            self.handle.publish(".tmp-conflict", PUBLISHED, b'{"changed":true}')
        self.assert_record()
        after = os.stat(PUBLISHED, dir_fd=self.descriptor, follow_symlinks=False)
        self.assertEqual((after.st_dev, after.st_ino), (original.st_dev, original.st_ino))
        self.assertEqual(os.listdir(self.descriptor), [PUBLISHED])
        self.assert_poisoned()

    def test_cleanup_failure_retains_only_temporary_and_poisoned_handle(self):
        self.recover()
        write_failure = OSError(errno.EIO, "injected initial write failure")
        cleanup_failure = OSError(errno.EACCES, "injected cleanup failure")
        with mock.patch.object(journal.os, "write", side_effect=write_failure), \
                mock.patch.object(journal.os, "unlink", side_effect=cleanup_failure):
            with self.assertRaises(OSError):
                self.handle.publish(TEMPORARY, PUBLISHED, RECORD)
        self.assertEqual(os.listdir(self.descriptor), [TEMPORARY])
        self.assertFalse((self.path / PUBLISHED).exists())
        self.assert_poisoned()
        # Existing witness startup owns temporary-file validation/removal. This
        # fixture callback exercises real removal before the helper barrier.
        fresh = self.new_handle()

        def cleanup_scan():
            metadata = os.stat(TEMPORARY, dir_fd=self.descriptor, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(metadata.st_nlink, 1)
            os.unlink(TEMPORARY, dir_fd=self.descriptor)
            return self.stamp()

        fresh.recover(cleanup_scan)
        self.assertEqual(os.listdir(self.descriptor), [])
        fresh.require_ready()

    def test_explicit_poison_cannot_be_cleared_by_a_recovered_handle(self):
        self.recover()
        self.handle.poison()
        self.handle.poison()
        self.assert_poisoned()
        self.assertEqual(os.listdir(self.descriptor), [])

    def test_poison_during_recovery_cannot_be_overwritten_by_success(self):
        for stage in ("scan", "barrier"):
            with self.subTest(stage=stage):
                handle = self.new_handle()
                real_fsync = os.fsync
                calls = []

                def scan():
                    if stage == "scan":
                        handle.poison()
                    return self.stamp()

                def fsync(descriptor):
                    calls.append(descriptor)
                    real_fsync(descriptor)
                    if stage == "barrier":
                        handle.poison()

                with mock.patch.object(journal.os, "fsync", side_effect=fsync):
                    with self.assertRaises(journal.JournalError):
                        handle.recover(scan)
                self.assertEqual(calls, [] if stage == "scan" else [self.descriptor])
                self.assert_poisoned(handle)

    def test_recovery_requires_exact_scan_stamp_before_and_after_barrier(self):
        accepted = self.stamp()
        for value in (None, list(accepted), accepted[:3], (True, *accepted[1:]),
                      (accepted[0] + 1, *accepted[1:])):
            with self.subTest(stamp=value):
                handle = self.new_handle()
                with mock.patch.object(journal.os, "fsync", side_effect=AssertionError("invalid scan reached barrier")):
                    with self.assertRaises(journal.JournalError):
                        handle.recover(lambda: value)
                self.assert_poisoned(handle)

        # Deliberately return an older *real* directory stamp after modifying
        # its mode. No timestamp-resolution assumptions or fabricated fstat.
        handle = self.new_handle()

        def changed_after_scan():
            before = self.stamp()
            os.chmod(self.path, 0o500)
            os.utime(self.path, ns=(0, 1_000_000_000))
            return before

        try:
            with mock.patch.object(journal.os, "fsync", side_effect=AssertionError("changed scan reached barrier")):
                with self.assertRaises(journal.JournalError):
                    handle.recover(changed_after_scan)
        finally:
            os.chmod(self.path, 0o700)
        self.assert_poisoned(handle)

        handle = self.new_handle()
        real_fsync = os.fsync

        def changed_during_barrier(descriptor):
            real_fsync(descriptor)
            os.utime(self.path, ns=(0, 2_000_000_000))

        with mock.patch.object(journal.os, "fsync", side_effect=changed_during_barrier):
            with self.assertRaises(journal.JournalError):
                handle.recover(self.stamp)
        self.assert_poisoned(handle)

    def test_rejected_names_and_bytes_never_open_a_file(self):
        self.recover()
        invalid = (
            ("../escape", PUBLISHED, RECORD), ("/absolute", PUBLISHED, RECORD),
            (".", PUBLISHED, RECORD), ("..", PUBLISHED, RECORD),
            ("", PUBLISHED, RECORD), ("é", PUBLISHED, RECORD),
            ("a" * 256, PUBLISHED, RECORD), (TEMPORARY, "x/y", RECORD),
            (TEMPORARY, TEMPORARY, RECORD), (TEMPORARY, PUBLISHED, b""),
            (TEMPORARY, PUBLISHED, b"x" * 1025),
            (TEMPORARY, PUBLISHED, bytearray(RECORD)),
            (TEMPORARY, PUBLISHED, RECORD.decode("ascii")),
        )
        with mock.patch.object(journal.os, "open", side_effect=AssertionError("invalid input performed I/O")):
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(journal.JournalError):
                        self.handle.publish(*arguments)
                    self.handle.require_ready()
        self.assertEqual(os.listdir(self.descriptor), [])


def witness_source():
    path = ROOT / "serverware/authority_witness.py"
    if path.stat().st_size > 512 * 1024:
        raise AssertionError("witness source exceeds fixture inspection bound")
    source = path.read_text(encoding="utf-8")
    parsed = ast.parse(source)
    stores = [node for node in parsed.body
              if isinstance(node, ast.ClassDef) and node.name == "WitnessStateStore"]
    if len(stores) != 1:
        raise AssertionError("witness store source is not unique")
    methods = {node.name: node for node in stores[0].body if isinstance(node, ast.FunctionDef)}
    return source, parsed, methods


def calls(node, expression):
    return [child for child in ast.walk(node)
            if isinstance(child, ast.Call) and ast.unparse(child.func) == expression]


def is_ready_statement(statement):
    return (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
            and ast.unparse(statement.value.func) == "self._journal_io.require_ready")


class WitnessJournalSourceLinkageTests(unittest.TestCase):
    """Source-only wiring assertions, not guarded-witness execution."""

    def test_guarded_witness_uses_shared_helper_after_flock_and_before_activation(self):
        source, parsed, methods = witness_source()
        imports = [node for node in parsed.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_witness_journal"]
        self.assertEqual(len(imports), 1)
        self.assertEqual({(item.name, item.asname) for item in imports[0].names},
                         {("JournalConflict", None), ("WitnessJournalIO", None)})
        constructor = methods["__init__"]
        flock = calls(constructor, "fcntl.flock")
        create = calls(constructor, "WitnessJournalIO")
        recovery = calls(constructor, "self._journal_io.recover")
        activation = calls(constructor, "self._persist_generation_activation")
        self.assertEqual(tuple(map(len, (flock, create, recovery, activation))), (1, 1, 1, 1))
        self.assertLess(flock[0].lineno, create[0].lineno)
        self.assertLess(create[0].lineno, recovery[0].lineno)
        self.assertLess(recovery[0].lineno, activation[0].lineno)
        self.assertEqual(ast.unparse(recovery[0].args[0]), "self._load_state")
        constructor_source = ast.get_source_segment(source, constructor)
        self.assertIn("self.lock = self._journal_io.lock", constructor_source)
        self.assertIn("self.state_directory_change = validated_stamp[2:]", constructor_source)
        self.assertEqual(calls(constructor, "self._load_state"), [])
        self.assertNotIn("def _rename_noreplace(", source)

    def test_every_transition_lock_and_replay_reader_checks_same_poison_latch(self):
        _source, _parsed, methods = witness_source()
        transition = methods["transition_bytes"]
        self.assertTrue(is_ready_statement(transition.body[0]))
        protected = [node for node in ast.walk(transition) if isinstance(node, ast.With)
                     and any(ast.unparse(item.context_expr) == "self.lock" for item in node.items)]
        self.assertEqual(len(protected), 3)
        for block in protected:
            self.assertTrue(is_ready_statement(block.body[0]))
        returns = [node for node in ast.walk(transition) if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 4)
        for returned in returns:
            self.assertTrue(any(returned in tuple(ast.walk(block)) for block in protected))
        for name in ("_read_transition_record", "_read_receipt_response", "_persist_generation_activation"):
            method = methods[name]
            self.assertIsInstance(method.body[0], ast.With)
            self.assertEqual(ast.unparse(method.body[0].items[0].context_expr),
                             "self._journal_io.ready()")

    def test_publication_and_index_acceptance_failures_poison_before_replay(self):
        source, _parsed, methods = witness_source()
        persist = methods["_persist_state_record"]
        self.assertIsInstance(persist.body[0], ast.With)
        self.assertEqual(ast.unparse(persist.body[0].items[0].context_expr), "self._journal_io.ready()")
        publish = calls(persist, "self._journal_io.publish")
        self.assertEqual(len(publish), 1)
        publication_tries = [node for node in ast.walk(persist) if isinstance(node, ast.Try)
                             and publish[0] in tuple(ast.walk(node))]
        self.assertEqual(len(publication_tries), 1)
        guarded = publication_tries[0]
        self.assertEqual({ast.unparse(handler.type) for handler in guarded.handlers},
                         {"JournalConflict", "BaseException"})
        for handler in guarded.handlers:
            self.assertEqual(len(calls(handler, "self._journal_io.poison")), 1)
            self.assertIsInstance(handler.body[-1], ast.Raise)
        counters = [node for node in ast.walk(guarded) if isinstance(node, ast.AugAssign)]
        self.assertEqual({ast.unparse(node.target) for node in counters},
                         {"self.state_sequence", "self.state_record_count", "self.state_total_bytes"})
        self.assertTrue(all(node.lineno > publish[0].lineno for node in counters))

        accept = methods["_persist_and_accept_state_record"]
        self.assertIsInstance(accept.body[0], ast.With)
        self.assertEqual(ast.unparse(accept.body[0].items[0].context_expr), "self._journal_io.ready()")
        stored = calls(accept, "self._persist_state_record")
        indexed = calls(accept, "self._accept_stored_state_record")
        self.assertEqual((len(stored), len(indexed)), (1, 1))
        self.assertLess(stored[0].lineno, indexed[0].lineno)
        accept_tries = [node for node in ast.walk(accept) if isinstance(node, ast.Try)
                        and indexed[0] in tuple(ast.walk(node))]
        self.assertEqual(len(accept_tries), 1)
        handler = accept_tries[0].handlers[0]
        self.assertEqual(ast.unparse(handler.type), "BaseException")
        self.assertEqual(len(calls(handler, "self._journal_io.poison")), 1)
        self.assertIsInstance(handler.body[-1], ast.Raise)
        for name in ("transition_bytes", "_persist_generation_activation"):
            self.assertEqual(len(calls(methods[name], "self._persist_and_accept_state_record")), 1)
            self.assertEqual(calls(methods[name], "self._accept_stored_state_record"), [])
        accept_callers = {name for name, method in methods.items()
                          if calls(method, "self._accept_stored_state_record")}
        self.assertEqual(accept_callers, {"_load_state", "_persist_and_accept_state_record"})
        self.assertIn("self._persist_and_accept_state_record(state_record)\n            return response_bytes",
                      ast.get_source_segment(source, methods["transition_bytes"]))

    def test_recovery_returns_validated_stamp_and_helper_imports_no_authority(self):
        source, _parsed, methods = witness_source()
        load = ast.get_source_segment(source, methods["_load_state"])
        self.assertIn("directory_identity_after.st_dev", load)
        self.assertIn("directory_identity_after.st_ino", load)
        self.assertIn("directory_identity_after.st_mtime_ns", load)
        self.assertIn("directory_identity_after.st_ctime_ns", load)
        self.assertIn("witness state is below its externally pinned high-water", load)
        helper_path = ROOT / "serverware/authority_witness_journal.py"
        self.assertLessEqual(helper_path.stat().st_size, 32 * 1024)
        helper = ast.parse(helper_path.read_text(encoding="utf-8"))
        self.assertEqual({node.module for node in helper.body if isinstance(node, ast.ImportFrom)},
                         {"__future__", "collections.abc", "contextlib"})
        self.assertEqual({item.name for node in helper.body if isinstance(node, ast.Import) for item in node.names},
                         {"ctypes", "errno", "os", "re", "stat", "threading"})


if __name__ == "__main__":
    unittest.main()
