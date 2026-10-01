#!/usr/bin/env python3
"""Bounded local-admission controls; not a signed package or serving claim."""
from __future__ import annotations

import ast
import fcntl
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_launcher as launcher
from serverware import authority_fd_entrypoint as entrypoint
from serverware import authority_stage_zero_contract as contract


class LocalAdmissionControls(unittest.TestCase):
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
