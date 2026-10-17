"""Focused real-descriptor delivery checks; no service admission is asserted."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_fd_entrypoint as entry


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


class LocalEntrypointTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0 or os.getegid() != 0:
            self.fail("run these descriptor controls in the isolated root test container")
        self.owned = []
        self.parent, self.child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.parent.close)
        self.addCleanup(self.child.close)
        self.setup = {"schema": entry.LOCAL_ADMISSION_SCHEMA, "role": "issuer",
                      "retainedFiles": [], "retainedDirectories": [],
                      "mutableStateDescriptors": [], "reservations": {}}
        for name, target in (("manifest", 256), ("certificate", 257), ("evidence", 258)):
            try:
                os.fstat(target)
            except OSError:
                pass
            else:
                self.fail("test must not overwrite an existing descriptor")
            original = self.seal(b"")
            observed = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, target)
            self.owned.append(observed)
            self.assertEqual(observed, target)
            metadata = os.fstat(observed)
            self.setup["reservations"][name] = {
                "fd": target, "device": metadata.st_dev, "inode": metadata.st_ino}

    def tearDown(self):
        for descriptor in reversed(self.owned):
            try:
                os.close(descriptor)
            except OSError:
                pass  # The real entrypoint owns and closes its handed-off copy.

    def seal(self, raw):
        descriptor = os.memfd_create("local-entrypoint-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.owned.append(descriptor)
        os.write(descriptor, raw)
        os.fchmod(descriptor, 0o400)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        return descriptor

    def selection(self):
        raw = canonical(self.setup)
        return self.seal(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), self.child.fileno()

    def test_actual_empty_reserved_slots_are_preserved_without_authority_bytes(self):
        selection = self.selection()
        descriptors = entry._local_admission_sources("issuer", selection)
        self.assertEqual(set(descriptors), {selection[0], selection[2], 256, 257, 258})
        for descriptor in descriptors:
            self.assertTrue(os.get_inheritable(descriptor))
        self.assertEqual([os.pread(fd, 1, 0) for fd in (256, 257, 258)], [b"", b"", b""])

    def test_changed_digest_and_reservation_identity_refuse_without_replacement(self):
        selection = self.selection()
        before = [(os.fstat(fd).st_ino, os.pread(fd, 1, 0)) for fd in (256, 257, 258)]
        with self.assertRaisesRegex(RuntimeError, "digest differs"):
            entry._local_admission_sources("issuer", (selection[0], "sha256:" + "0" * 64, selection[2]))
        self.setup["reservations"]["manifest"]["inode"] += 1
        with self.assertRaisesRegex(RuntimeError, "original empty slot"):
            entry._local_admission_sources("issuer", self.selection())
        self.assertEqual(before, [(os.fstat(fd).st_ino, os.pread(fd, 1, 0)) for fd in (256, 257, 258)])

    def test_reused_slot_in_static_inventory_refuses(self):
        self.setup["retainedFiles"] = [256]
        with self.assertRaisesRegex(RuntimeError, "overlap"):
            entry._local_admission_sources("issuer", self.selection())

    def test_late_selection_cannot_enter_native_or_control_plane(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(RuntimeError, "fixed authority selection"):
            entry._normal_main("issuer", local_admission=(10, "sha256:" + "0" * 64, 11))
        with patch.dict(os.environ, {"CATCHPLATE_AUTHORITY_TRUST_MODE": "trusted-host-local"}, clear=True), \
                self.assertRaisesRegex(RuntimeError, "fixed authority selection"):
            entry._normal_main("control-plane", local_admission=(10, "sha256:" + "0" * 64, 11))

    def test_cli_forwards_only_exact_public_descriptor_arguments(self):
        arguments = ["entry", "issuer", "--local-admission-fd", "10", "--local-admission-sha256",
                     "sha256:" + "a" * 64, "--local-admission-channel-fd", "11"]
        with patch.object(sys, "argv", arguments), patch.object(entry, "_normal_main", return_value=7) as dispatch:
            self.assertEqual(entry.main(), 7)
            dispatch.assert_called_once_with("issuer", local_admission=(10, arguments[5], 11))
        arguments[3] = "010"
        with patch.object(sys, "argv", arguments), self.assertRaisesRegex(RuntimeError, "not canonical"):
            entry.main()

    def test_exec_handoff_skips_late_credentials_and_removes_ambient_secrets(self):
        selection = self.selection()
        opened = []
        captured = {}

        def credential(name):
            opened.append(name)
            return self.seal(b"static fixture, not actual credential authority")

        def execute(path, arguments, environment):
            captured.update(path=path, arguments=arguments, environment=environment)
            raise InterruptedError("captured final exec boundary")

        ambient = {"CATCHPLATE_AUTHORITY_TRUST_MODE": "trusted-host-local",
                   "CATCHPLATE_METADATA_STORE_ADMIN_POSTGRES_DSN": "must-never-cross",
                   "UNRELATED_SECRET": "must-never-cross", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        # Duplicate the channel: the real entrypoint consumes its inherited copy.
        duplicate = os.dup(selection[2])
        with patch.dict(os.environ, ambient, clear=True), \
                patch.object(entry, "_consume_socket_activation", side_effect=lambda role: self.seal(b"listener fixture")), \
                patch.object(entry, "_open_systemd_credential", side_effect=credential), \
                patch.object(entry, "_open_source", side_effect=lambda *args, **kwargs: self.seal(b"bootstrap fixture")), \
                patch.object(os, "execve", side_effect=execute), \
                self.assertRaisesRegex(InterruptedError, "final exec"):
            entry._normal_main("issuer", local_admission=(selection[0], selection[1], duplicate))
        self.assertNotIn("catchplate-authority-launch-certificate", opened)
        self.assertFalse(any("launch-manifest" in name or "attestation" in name for name in opened))
        self.assertEqual(captured["path"], "/runtime/python/bin/python3")
        self.assertEqual(captured["environment"]["CATCHPLATE_AUTHORITY_LAUNCH_CERTIFICATE_FD"], "257")
        self.assertTrue(set(captured["environment"]) <= entry.LOCAL_EXEC_ENVIRONMENT)
        self.assertNotIn("must-never-cross", canonical(captured).decode())
        self.assertIn("CATCHPLATE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD=256", captured["arguments"])
        self.assertIn("CATCHPLATE_POLICY_AUTHORITY_ATTESTATION_FD=258", captured["arguments"])


if __name__ == "__main__":
    unittest.main()
