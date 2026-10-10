#!/usr/bin/env python3
"""Pure notification key-file and envelope tests; no configured owner or network."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import operator_notification_custody as custody


class NotificationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="notification-custody-pure-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "custody"
        self.directory.mkdir(mode=0o700)
        self.file = self.directory / custody.FILENAME
        self.key = custody.Key(str(uuid.uuid4()), os.urandom(32))

    def initialize(self):
        # Only this pure file primitive's already-reviewed ownership assertion is
        # stubbed. The connected store suite uses the real publication lock.
        with patch("serverware.operator_publication.assert_held"):
            return custody.initialize(self.directory, no_retained_notification_state=True)

    def test_read_missing_never_initializes(self):
        with self.assertRaisesRegex(custody.CustodyError, "^operator notification custody unavailable$"):
            custody.read(self.directory, self.key.owner_id)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_explicit_initialization_is_durable_closed_and_no_overwrite(self):
        key = self.initialize()
        info, raw = self.file.stat(), self.file.read_bytes()
        self.assertEqual(info.st_mode & 0o777, 0o600)
        self.assertEqual(custody.read(self.directory, key.owner_id), key)
        self.assertEqual(self.initialize(), key)
        self.assertEqual((self.file.stat().st_ino, self.file.read_bytes()), (info.st_ino, raw))
        self.assertNotIn("material", repr(key))
        self.assertEqual(set(json.loads(raw)), {"schema", "owner_id", "key"})

    def test_nonempty_other_namespace_is_not_adopted(self):
        (self.directory / "other-state").touch(mode=0o600)
        with self.assertRaises(custody.CustodyError):
            self.initialize()
        self.assertFalse(self.file.exists())

    def test_invalid_or_partial_existing_record_is_never_repaired(self):
        self.file.write_bytes(b"partial-notification-key")
        self.file.chmod(0o600)
        raw = self.file.read_bytes()
        with self.assertRaises(custody.CustodyError):
            self.initialize()
        self.assertEqual(self.file.read_bytes(), raw)

    def test_unknown_record_fields_or_wrong_owner_refuse(self):
        key = self.initialize()
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, self.key.owner_id)
        record = json.loads(self.file.read_bytes())
        record["extra"] = "not-an-owner-contract"
        self.file.write_bytes(custody._canonical(record) + b"\n")
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, key.owner_id)

    def test_key_file_and_directory_permissions_fail_closed(self):
        key = self.initialize()
        self.file.chmod(0o640)
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, key.owner_id)
        self.file.chmod(0o600)
        self.directory.chmod(0o750)
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, key.owner_id)
        self.directory.chmod(0o700)

    def test_symlink_and_hardlink_refused(self):
        key = self.initialize()
        held = self.directory.parent / "held-key"
        self.file.rename(held)
        self.file.symlink_to(held)
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, key.owner_id)
        self.file.unlink()
        os.link(held, self.file)
        with self.assertRaises(custody.CustodyError):
            custody.read(self.directory, key.owner_id)
        alias = self.directory.parent / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(custody.CustodyError):
            custody.read(alias, key.owner_id)

    def test_envelope_binds_owner_slot_adapter_revision_and_authenticates(self):
        secret = "https://receiver.example.com/synthetic-only-secret"
        nonce, ciphertext = custody.seal(self.key, "audit_log.webhook", 1, secret)
        self.assertNotIn(secret.encode(), ciphertext)
        self.assertEqual(custody.unseal(self.key, "audit_log.webhook", 1, nonce, ciphertext), secret)
        for key, slot, revision, data in ((self.key, "audit_log.slack", 1, ciphertext),
                (self.key, "action_required.webhook", 1, ciphertext),
                (self.key, "audit_log.webhook", 2, ciphertext),
                (custody.Key(str(uuid.uuid4()), self.key.material), "audit_log.webhook", 1, ciphertext),
                (self.key, "audit_log.webhook", 1, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))):
            with self.assertRaises(custody.CustodyError):
                custody.unseal(key, slot, revision, nonce, data)

    def test_init_requires_explicit_empty_store_proof_and_publication(self):
        with patch("serverware.operator_publication.assert_held"):
            with self.assertRaises(custody.CustodyError):
                custody.initialize(self.directory, no_retained_notification_state=False)
        with self.assertRaises(custody.CustodyError):
            custody.initialize(self.directory, no_retained_notification_state=True)
        self.assertFalse(self.file.exists())


if __name__ == "__main__":
    unittest.main()
