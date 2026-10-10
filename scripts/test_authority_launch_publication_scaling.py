#!/usr/bin/env python3
"""Real local O_TMPFILE/linkat controls with explicitly synthetic owner guards.

No process admission, signing, launch, provider, or startup-latency acceptance.
Fault tests intercept writes only to inject partial I/O/errors; successful
publication, descriptor checks, byte readback, and no-replace use real syscalls.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_local_launch_authorization as subject


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix="launch-publication-scaling-") as path:
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        value = SimpleNamespace(path=Path(path), directory=directory, held=[], events=[], linked=[])
        try:
            yield value
        finally:
            for fd in reversed(value.held):
                os.close(fd)
            os.close(directory)


def publish(value, raw, *, check=None, check_io=None):
    return subject.publish_late_original(value.directory, "evidence.json", raw,
        hold=value.held.append,
        check=(lambda: value.events.append("full")) if check is None else check,
        check_io=check_io, linked=lambda: value.linked.append(True))


class PublicationScalingTests(unittest.TestCase):
    def test_full_sweeps_constant_while_chunk_guards_and_real_bytes_scale(self):
        for chunks in (1, 4):
            raw = b"public fixture\n" * ((chunks * 65536) // 15)
            actual_chunks = (len(raw) + 65535) // 65536
            self.assertEqual(actual_chunks, chunks)
            with fixture() as value:
                fd = publish(value, raw, check_io=lambda: value.events.append("io"))
                self.assertEqual(value.events.count("full"), 3)
                self.assertGreaterEqual(value.events.count("io"), 6 * chunks)
                self.assertEqual(value.linked, [True])
                self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
                current = os.fstat(fd)
                self.assertEqual((stat.S_IMODE(current.st_mode), current.st_size, current.st_nlink),
                    (0o400, len(raw), 1))
                self.assertEqual(os.stat("evidence.json", dir_fd=value.directory).st_ino, current.st_ino)
                with self.assertRaises(ValueError):
                    publish(value, raw, check_io=lambda: value.events.append("io"))
                self.assertEqual(value.linked, [True])
                self.assertEqual((value.path / "evidence.json").read_bytes(), raw)

    def test_default_retains_every_original_full_chunk_check(self):
        raw = b"x" * (3 * 65536)
        with fixture() as value:
            publish(value, raw)
            self.assertEqual(value.events, ["full"] * (3 * 3 + 3))
        with fixture() as value:
            with self.assertRaises(ValueError):
                publish(value, raw, check_io=True)
            self.assertEqual((value.events, value.held, value.linked), ([], [], []))
            self.assertEqual(os.listdir(value.directory), [])

    def test_partial_writes_continue_same_output_without_retrying_publication(self):
        real_write = os.write
        calls = []
        def partial(fd, raw):
            calls.append(fd)
            return real_write(fd, raw[:997])
        raw = b"a" * (65536 + 7)
        with fixture() as value, patch.object(subject.os, "write", side_effect=partial):
            fd = publish(value, raw, check_io=lambda: value.events.append("io"))
            self.assertGreater(len(calls), 2)
            self.assertEqual(set(calls), {fd})
            self.assertEqual(value.events.count("full"), 3)
            self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
            self.assertEqual(value.linked, [True])

    def test_write_error_or_zero_retains_partial_anonymous_output_without_link(self):
        real_write = os.write
        for failure in (OSError("synthetic write failure"), 0):
            with self.subTest(failure=type(failure).__name__), fixture() as value:
                writes = []
                def failing(fd, raw):
                    writes.append(fd)
                    if len(writes) == 1:
                        return real_write(fd, raw[:13])
                    if isinstance(failure, BaseException):
                        raise failure
                    return failure
                with patch.object(subject.os, "write", side_effect=failing):
                    with self.assertRaises((OSError, ValueError)):
                        publish(value, b"a" * 100, check_io=lambda: None)
                self.assertEqual(len(writes), 2)
                self.assertEqual(os.pread(value.held[0], 101, 0), b"a" * 13)
                self.assertEqual((value.linked, os.listdir(value.directory)), ([], []))
                self.assertEqual(os.fstat(value.held[0]).st_nlink, 0)

    def test_fresh_io_refusal_and_cancellation_propagate_without_link(self):
        for failure in (ValueError("original deadline"), RuntimeError("original source"),
                ValueError("child no longer live"), KeyboardInterrupt()):
            with self.subTest(failure=str(failure)), fixture() as value:
                calls = []
                def check_io():
                    calls.append(True)
                    if len(calls) == 3:
                        raise failure
                with self.assertRaises(type(failure)) as caught:
                    publish(value, b"x" * (2 * 65536), check_io=check_io)
                self.assertIs(caught.exception, failure)
                self.assertEqual((value.linked, os.listdir(value.directory)), ([], []))
                self.assertEqual(os.fstat(value.held[0]).st_size, 65536)

    def test_changed_retained_roster_is_refused_by_full_prelink_sweep(self):
        with fixture() as value:
            original = value.path / "retained"
            original.write_bytes(b"public retained fixture")
            held = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
            value.held.append(held)
            identity = subject.io._identity(os.fstat(held))
            def check():
                value.events.append("full")
                subject.require(subject.io._identity(os.fstat(held)) == identity
                    and subject.io._identity(os.stat(original, follow_symlinks=False)) == identity)
            changed = []
            def check_io():
                if not changed:
                    replacement = value.path / "replacement"
                    replacement.write_bytes(b"different public fixture")
                    os.replace(replacement, original)
                    changed.append(True)
            with self.assertRaises(ValueError):
                publish(value, b"x" * 65537, check=check, check_io=check_io)
            self.assertEqual(value.events.count("full"), 2)
            self.assertEqual(value.linked, [])
            self.assertFalse((value.path / "evidence.json").exists())

    def test_active_output_mode_size_and_fd_substitution_are_refused(self):
        for mutation in ("mode", "size", "fd"):
            with self.subTest(mutation=mutation), fixture() as value:
                calls = []
                def check_io():
                    calls.append(True)
                    if len(calls) != 2:
                        return
                    fd = value.held[0]
                    if mutation == "mode":
                        os.fchmod(fd, 0o644)
                    elif mutation == "size":
                        os.ftruncate(fd, 1)
                    else:
                        replacement = os.memfd_create("synthetic-output-substitution", os.MFD_CLOEXEC)
                        try:
                            os.dup2(replacement, fd, inheritable=False)
                        finally:
                            os.close(replacement)
                with self.assertRaises(ValueError):
                    publish(value, b"x" * 65537, check_io=check_io)
                self.assertEqual((value.linked, os.listdir(value.directory)), ([], []))

    def test_actual_issuer_publish_switches_to_sources_only_after_final_link(self):
        # Only the publication method is under test. These are explicitly
        # synthetic owner guards and unsigned public strings, not issue/admit.
        for fail_after_release in (False, True):
            with self.subTest(fail_after_release=fail_after_release), fixture() as value:
                certificate, manifest = b"public certificate fixture", b"public manifest fixture" * 5000
                def parked(kind):
                    subject.require(not (value.path / "manifest.json").exists())
                    value.events.append(kind)
                def sources():
                    self.assertTrue((value.path / "manifest.json").exists())
                    value.events.append("sources")
                    if fail_after_release:
                        raise ValueError("synthetic post-release original deadline")
                owner = SimpleNamespace(directory=value.directory, _hold=value.held.append,
                    issue=lambda: (certificate, manifest), check=lambda: parked("full"),
                    _check_live=lambda: parked("live"), check_sources=sources)
                if fail_after_release:
                    with self.assertRaises(subject.LocalLaunchAuthorizationError) as caught:
                        subject.LocalLaunchAuthorizationIssuer.publish(owner)
                    self.assertIs(caught.exception.owner, owner)
                else:
                    result = subject.LocalLaunchAuthorizationIssuer.publish(owner)
                    self.assertEqual(result, {name: "sha256:" + hashlib.sha256(raw).hexdigest()
                        for name, raw in zip(subject.OUTPUT_NAMES, (certificate, manifest))})
                    self.assertEqual(value.events.count("full"), 5)
                    first_source = value.events.index("sources")
                    self.assertTrue(all(event == "sources" for event in value.events[first_source:]))
                self.assertEqual((value.path / "certificate.json").read_bytes(), certificate)
                self.assertEqual((value.path / "manifest.json").read_bytes(), manifest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
