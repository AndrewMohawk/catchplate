#!/usr/bin/env python3
"""Fixed command grammar and real public seals, not an installer launch.

No installed runtime, live process owner, approval or successful reap is faked.
The parent process's full EOF/exit/reap path still needs protected integration.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import native_pilot_genesis_install_runtime_entrypoint as entry
from scripts import native_pilot_runtime_artifacts as artifact
from catchplate import native_pilot_genesis_installer_process as process

p = process.p


def pairs(kind):
    names = ("supervisor_inventory",) + (("configuration",) if kind == "job" else ()) + (
        "request", "input", "approval")
    return {name: (index + 3, p.sha(name.encode("ascii"))) for index, name in enumerate(names)}


class InstallerCommandControls(unittest.TestCase):
    def test_two_fixed_commands_join_packaged_entrypoint(self):
        for kind in ("rendezvous", "job"):
            with self.subTest(kind=kind):
                command, inherited = process.command(kind, pairs(kind))
                self.assertEqual(command[:4], ["/runtime/python/bin/python3", "-I", "-B", entry.SCRIPT])
                mode, fd, pin, forwarded = entry.arguments(command[4:])
                self.assertEqual(mode, "--install-" + kind)
                self.assertEqual((fd, pin), pairs(kind)["supervisor_inventory"])
                self.assertEqual(len(forwarded), 16 if kind == "job" else 12)
                self.assertEqual(len(inherited), 5 if kind == "job" else 4)

    def test_no_arbitrary_installer_or_unlisted_input(self):
        for kind, values in (("arbitrary", pairs("job")), ("rendezvous", pairs("job")),
                ("job", pairs("rendezvous")), ("rendezvous", pairs("rendezvous") | {"path": (8, p.sha(b"x"))})):
            with self.subTest(kind=kind), self.assertRaises(ValueError): process.command(kind, values)

    def test_descriptor_and_pin_cannot_be_defaulted(self):
        for bad in ((3, p.sha(b"duplicate")), (True, p.sha(b"bool")), (2, p.sha(b"stdio")),
                (8, "sha256:" + "G" * 64), (1 << 31, p.sha(b"oversized"))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                process.command("rendezvous", pairs("rendezvous") | {"input": bad})

    def test_entrypoint_refuses_ambiguous_flags_and_descriptors(self):
        command, _ = process.command("rendezvous", pairs("rendezvous"))
        values = command[4:]
        variants = (values[:-1], values + ["extra"], ["--install-unknown", *values[1:]],
            values[:2] + ["03"] + values[3:], values[:6] + ["3"] + values[7:],
            values[:5] + ["--request-path", *values[6:]], values[:4] + ["none", *values[5:]])
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError): entry.arguments(changed)

    def test_installer_scripts_are_exact_supervisor_inventory_members(self):
        for name in ("native_pilot_genesis_install_runtime_entrypoint.py",
                "install_native_pilot_genesis_rendezvous.py", "install_native_pilot_genesis_job.py"):
            self.assertEqual(artifact.SUPERVISOR_FILES.count("scripts/" + name), 1)
        self.assertNotIn("scripts/install_native_pilot_genesis_job.py", artifact.AUTHORITY_FILES)

    def test_live_owner_cannot_be_constructed_from_a_value(self):
        for owner in (process.GenesisInstallerProcess, process.SealedRequest):
            with self.subTest(owner=owner), self.assertRaises(ValueError): owner(object())


@unittest.skipUnless(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0),
    "requires private user namespace mapped to root")
class ActualSealedRequestControls(unittest.TestCase):
    def test_actual_descriptor_contains_only_literal_request(self):
        raw = b'{"observation":"literal public request, not approval"}'
        owner = process.SealedRequest.open(raw)
        try:
            owner.check()
            self.assertEqual(owner.raw, raw)
            self.assertEqual(owner.digest, p.sha(raw))
            self.assertEqual(os.pread(owner.fd, len(raw) + 1, 0), raw)
            self.assertEqual(fcntl.fcntl(owner.fd, fcntl.F_GET_SEALS), process.public.SEALS)
            self.assertEqual(os.fstat(owner.fd).st_mode & 0o777, 0o400)
            self.assertFalse(os.get_inheritable(owner.fd))
        finally:
            owner.close()

    def test_actual_seal_rejects_write_and_truncation(self):
        owner = process.SealedRequest.open(b'{}')
        try:
            with self.assertRaises(OSError): os.pwrite(owner.fd, b"x", 0)
            with self.assertRaises(OSError): os.ftruncate(owner.fd, 0)
            owner.check()
        finally:
            owner.close()

    def test_distinct_real_requests_have_distinct_file_identity(self):
        first, second = process.SealedRequest.open(b'{}'), None
        try:
            second = process.SealedRequest.open(b'{}')
            self.assertNotEqual((os.fstat(first.fd).st_dev, os.fstat(first.fd).st_ino),
                (os.fstat(second.fd).st_dev, os.fstat(second.fd).st_ino))
            self.assertEqual(first.digest, second.digest)
        finally:
            if second is not None: second.close()
            first.close()

    def test_closed_request_cannot_be_reused(self):
        owner = process.SealedRequest.open(b'{}')
        owner.close()
        with self.assertRaises(ValueError): owner.check()
        owner.close()


if __name__ == "__main__":
    unittest.main()
