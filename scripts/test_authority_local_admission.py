#!/usr/bin/env python3
"""Bounded local-admission controls; not a signed package or serving claim."""
from __future__ import annotations

import ast
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_launcher as launcher
from serverware import authority_fd_entrypoint as entrypoint
from serverware import authority_stage_zero_contract as contract


class LocalAdmissionControls(unittest.TestCase):
    def test_local_retained_limits_match_signed_contract_without_widening_control_slots(self):
        self.assertEqual(entrypoint.LOCAL_RETAINED_FILES_MAX, launcher.MAX_CLOSURE_FILES)
        self.assertEqual(entrypoint.LOCAL_RETAINED_FILES_MAX, contract.MAX_RETAINED_FILES)
        self.assertEqual(entrypoint.LOCAL_RETAINED_DIRECTORIES_MAX, contract.MAX_RETAINED_DIRECTORIES)
        source = (ROOT / "serverware" / "authority_fd_entrypoint.py").read_text()
        tree = ast.parse(source)
        method = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_local_admission_sources")
        text = ast.get_source_segment(source, method)
        self.assertIn("4 <= fd <= 1023 for fd in (setup_fd, channel_fd)", text)
        self.assertIn("32 <= descriptor <= 1023", text)

    def test_actual_local_entry_accepts_high_retained_roster_with_low_original_slots(self):
        # This exercises descriptor framing/type custody, not signed admission.
        self.assertEqual(os.geteuid(), 0)
        handles, channels = [], []
        def hold(fd):
            handles.append(fd)
            return fd
        def sealed(raw, target=None):
            fd = hold(os.memfd_create("local-high-roster-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
            if raw:
                self.assertEqual(os.write(fd, raw), len(raw))
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, launcher.REQUIRED_MEMFD_SEALS)
            if target is not None:
                retained = hold(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, target))
                self.assertEqual(retained, target)  # Never overwrite another FD.
                os.close(fd); handles.remove(fd)
                fd = retained
            return fd
        try:
            hold(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
            channels.extend(socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC))
            self.assertTrue(all(4 <= channel.fileno() <= 1023 for channel in channels))
            reservations = {}
            for purpose in ("manifest", "certificate"):
                fd = sealed(b"", launcher.LOCAL_SLOTS[purpose])
                info = os.fstat(fd)
                reservations[purpose] = dict(fd=fd, device=info.st_dev, inode=info.st_ino)
            original = sealed(b"genuine retained public bytes")
            files = [hold(fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 1024)) for _ in range(137)]
            directory = hold(os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
            retained_directory = hold(fcntl.fcntl(directory, fcntl.F_DUPFD_CLOEXEC, 1024))
            raw = launcher._canonical(dict(schema=launcher.LOCAL_SETUP_SCHEMA, role="runtime",
                reservations=reservations, retainedFiles=files, retainedDirectories=[retained_directory],
                mutableStateDescriptors=[]))
            setup = sealed(raw)
            selection = setup, "sha256:" + hashlib.sha256(raw).hexdigest(), channels[0].fileno()
            inherited = entrypoint._local_admission_sources("runtime", selection)
            self.assertTrue(set(files) <= set(inherited))
            self.assertIn(retained_directory, inherited)
            self.assertEqual(len(inherited), 2 + 2 + 137 + 1)
        finally:
            for channel in reversed(channels):
                channel.close()
            for fd in reversed(handles):
                os.close(fd)

    def test_canonical_original_is_literal_and_closed_to_lossy_decoding(self):
        raw = b'{"a":1,"b":"public"}'
        self.assertEqual(launcher._local_document(raw, 64), {"a": 1, "b": "public"})
        for changed in (b'{ "a":1}', b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'[]'):
            with self.subTest(changed=changed), self.assertRaises(launcher.LaunchError):
                launcher._local_document(changed, 64)
        with self.assertRaises(launcher.LaunchError):
            launcher._local_document(raw, len(raw) - 1)

    def test_actual_file_observation_reads_original_without_moving_offset(self):
        with tempfile.TemporaryFile() as stream:
            raw = b"actual public test original\n"
            stream.write(raw); stream.flush(); stream.seek(3)
            row = launcher._local_stat(stream.fileno())
            metadata = os.fstat(stream.fileno())
            self.assertEqual(row["sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual((row["device"], row["inode"], row["size"]),
                (metadata.st_dev, metadata.st_ino, len(raw)))
            self.assertEqual(stream.tell(), 3)

    @unittest.skipUnless(hasattr(os, "memfd_create"), "Linux sealed memfd required")
    def test_actual_empty_reservation_is_not_a_manifest(self):
        fd = os.memfd_create("local-reservation-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, launcher.REQUIRED_MEMFD_SEALS)
            self.assertEqual(launcher._require_sealed_descriptor_number(fd, label="empty reservation", maximum=16), b"")
            with self.assertRaises(launcher.LaunchError):
                launcher._local_document(b"", 16)
        finally:
            os.close(fd)

    def test_environment_allowlist_matches_both_actual_consumers(self):
        self.assertEqual(launcher.LOCAL_EXEC_ENVIRONMENT, entrypoint.LOCAL_EXEC_ENVIRONMENT)
        self.assertEqual(launcher.LOCAL_EXEC_ENVIRONMENT, contract.ALLOWED_ENVIRONMENT_KEYS)
        self.assertNotIn("SERVERWARE_POLICY_AUTHORITY_CONFIG_FD", launcher.LOCAL_EXEC_ENVIRONMENT)

    def test_local_boot_uses_existing_domain_not_a_new_plain_hash(self):
        self.assertEqual(launcher._local_boot(), launcher._boot_identity_digest())

    def test_fixed_slots_and_protocol_do_not_select_native_entry(self):
        self.assertEqual(launcher.LOCAL_SLOTS, {"manifest": 256, "certificate": 257, "evidence": 258})
        source = (ROOT / "serverware" / "authority_launcher.py").read_text()
        tree = ast.parse(source)
        enter = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_enter")
        text = ast.get_source_segment(source, enter)
        self.assertLess(text.index("parking.exchange()"), text.index("_load_manifest("))
        self.assertLess(text.index("_load_manifest("), text.index("parking.bind(payload)"))
        self.assertIn("not trusted_host_local or handoff_descriptor is not None", text)
        self.assertLess(text.index("authority_launch_guard.activate("), text.index("parking.finish_after_identity_drop()"))

    def test_source_fixed_reseal_preserves_original_and_native_close_default(self):
        source = (ROOT / "serverware" / "authority_launcher.py").read_text()
        tree = ast.parse(source)
        consume = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_consume_bootstrap_descriptor")
        self.assertEqual(ast.literal_eval(consume.args.kw_defaults[0]), True)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_LocalAdmission")
        reseal = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "credential_resealed")
        text = ast.get_source_segment(source, reseal)
        for name in ("sha256", "size", "uid", "gid", "mode", "_require_sealed_descriptor"):
            self.assertIn(name, text)
        self.assertIn("parking.credential_resealed(descriptor)", source)

    def test_temporary_rights_retire_before_signed_boundary_and_parent_rearms(self):
        source = (ROOT / "serverware" / "authority_launcher.py").read_text()
        tree = ast.parse(source)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_LocalAdmission")
        methods = {node.name: ast.get_source_segment(source, node) for node in owner.body if isinstance(node, ast.FunctionDef)}
        exchange = methods["exchange"]
        self.assertLess(exchange.index("while self.incoming:"), exchange.index("self.delivered = True"))
        self.assertIn("self.closing = True", exchange)
        rearm = methods["rearm_after_identity_drop"]
        self.assertIn("libc.prctl(1, signal.SIGTERM", rearm)
        self.assertGreaterEqual(rearm.count("os.getppid()"), 2)
        self.assertIn("self.close()", methods["finish_after_identity_drop"])


if __name__ == "__main__":
    unittest.main()
