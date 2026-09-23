#!/usr/bin/env python3
"""Real local signature/filesystem components, not installation authority proof.

The reconcile-only DB seam records journal inputs and completion ordering. It
never imports the DB/registry, issues a capability, or claims a committed DB
transition. Files, signing, validation, rollback planning and durable replacement
are real; injected I/O errors deliberately interrupt those real operations.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import serverware
from serverware import webauthn_trust as trust
from serverware import webauthn_trust_core as core


NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/webauthn-trust-bundle.v1.schema.json"


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class JournalRecorder(types.ModuleType):
    """Only a local ordering oracle; every unlisted DB operation fails."""

    def __init__(self, publication, before_completion, before_pending):
        super().__init__("serverware.db")
        self.publication = copy.deepcopy(publication)
        self.before_completion = before_completion
        self.before_pending = before_pending
        self.calls = []
        self.errors = []
        self.credentials = {"revoked-credential": {"revoked_at": "2024-12-31T00:00:00+00:00"}}

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        raise AssertionError(f"unexpected DB access: {name}")

    def get_pending_webauthn_trust_publication(self):
        self.before_pending()
        self.calls.append("pending")
        return copy.deepcopy(self.publication)

    def get_webauthn_credential_by_record_id(self, record_id, *, include_revoked):
        if include_revoked is not True:
            raise AssertionError("withdrawal read must include revoked credentials")
        self.calls.append(("credential", record_id))
        return copy.deepcopy(self.credentials.get(record_id))

    def complete_webauthn_trust_publication(self, publication_id):
        if publication_id != self.publication["id"]:
            raise AssertionError("completion publication changed")
        self.before_completion()
        self.calls.append(("complete", publication_id))
        return {"id": publication_id}

    def record_webauthn_trust_publication_error(self, publication_id, error):
        self.errors.append((publication_id, error))


class WebAuthnTrustInstallationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="webauthn-trust-installation-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle_path = self.root / "bundles" / "trust.json"
        self.state_path = self.root / "states" / "state.json"
        self.private_path = self.root / "signer.key"
        self.public_path = self.root / "signer.pub"
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        self.public_der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_path.write_bytes(self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        self.context = core.TrustVerificationContext(self.public_der, SCHEMA_PATH.read_bytes(), NOW)
        self.real_capture_context = trust._capture_verification_context
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.lock_depth = 0
        real_lock = trust.trust_bundle_lock
        @contextmanager
        def measured_lock(*, exclusive):
            # Keep the actual flock, but fail promptly if a regression nests
            # separately opened exclusive locks instead of hanging this test.
            if self.lock_depth != 0:
                raise AssertionError("nested trust-bundle lock acquisition")
            with real_lock(exclusive=exclusive):
                self.lock_depth += 1
                try:
                    yield
                finally:
                    self.lock_depth -= 1
        self.stack.enter_context(mock.patch.object(trust, "trust_bundle_lock", measured_lock))
        for name, value in {
            "WEBAUTHN_TRUST_BUNDLE_PATH": self.bundle_path,
            "WEBAUTHN_TRUST_BUNDLE_STATE_PATH": self.state_path,
            "WEBAUTHN_TRUST_SIGNING_KEY_PATH": self.private_path,
            "WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH": self.public_path,
        }.items():
            self.stack.enter_context(mock.patch.object(trust, name, value))
        self.stack.enter_context(mock.patch.object(trust, "ensure_data_dirs", lambda: None))
        # Explicit immutable verification input, not a mocked verification result.
        self.capture = self.stack.enter_context(mock.patch.object(trust, "_capture_verification_context", return_value=self.context))

    def bundle(self, sequence=1, **metadata):
        result = {
            "apiVersion": "serverware.webauthnTrust/v1",
            "kind": "WebAuthnTrustBundle",
            "metadata": {
                "id": "local-\u00e9-\U0001f511", "sequence": sequence, "rollbackEpoch": 1,
                "validFrom": "2024-01-01T00:00:00Z", "validUntil": "2026-01-01T00:00:00Z",
                "signingKeyId": sha256(self.public_der), **metadata,
            },
            "roots": [],
        }
        return self.sign(result)

    def sign(self, bundle):
        result = copy.deepcopy(bundle)
        result["metadata"].pop("signature", None)
        result["metadata"]["signature"] = "ed25519:" + base64.urlsafe_b64encode(
            self.key.sign(canonical(result)),
        ).decode("ascii").rstrip("=")
        return result

    def verified(self, bundle):
        return core.verify_bundle(canonical(bundle), self.context)

    def snapshot(self):
        return tuple(path.read_bytes() if path.exists() else None for path in (self.bundle_path, self.state_path))

    def assert_installed(self, bundle):
        verified = self.verified(bundle)
        self.assertEqual(self.bundle_path.read_bytes(), verified.installation_bytes)
        state = json.loads(self.state_path.read_bytes())
        self.assertEqual(state["bundle_digest"], verified.bundle_digest)
        self.assertEqual(state["sequence"], verified.sequence)
        self.assertEqual(state["rollback_epoch"], verified.rollback_epoch)
        self.assertEqual(core.plan_rollback(verified, self.state_path.read_bytes(), self.context), None)
        return verified

    def publication(self, bundle, *, previous=None):
        verified = self.verified(bundle)
        return {
            "id": "publication-local", "bundle": copy.deepcopy(bundle),
            "previous_bundle_digest": previous, "bundle_digest": verified.bundle_digest,
            "sequence": verified.sequence, "rollback_epoch": verified.rollback_epoch,
            "signing_key_id": verified.signing_key_id,
            "withdrawn_credential_ids": ["revoked-credential"],
        }

    @contextmanager
    def journal(self, publication, before_completion=None):
        recorder = JournalRecorder(publication,
            before_completion or (lambda: self.assert_installed(publication["bundle"])),
            lambda: self.assertEqual(self.lock_depth, 1, "journal lookup must be inside the installation lock"))
        with mock.patch.dict(sys.modules, {"serverware.db": recorder}), mock.patch.object(serverware, "db", recorder, create=True):
            yield recorder

    def assert_not_completed(self, recorder):
        self.assertFalse(any(isinstance(item, tuple) and item[0] == "complete" for item in recorder.calls))

    def test_real_signed_install_returns_exact_local_readback_and_private_modes(self):
        bundle = self.bundle()
        result = trust.write_trust_bundle(bundle)
        self.capture.assert_called_once_with()
        verified = self.assert_installed(bundle)
        self.assertEqual(result["digest"], verified.bundle_digest)
        self.assertEqual(result["root_count"], 0)
        observation = result["local_installation"]
        self.assertEqual(set(observation), {
            "schema", "bundleDigest", "bundleFileDigest", "stateFileDigest",
            "bundlePath", "statePath", "verifiedAt",
        })
        self.assertEqual(observation, {
            "schema": "serverware.webauthnLocalInstallationObservation/v1",
            "bundleDigest": verified.bundle_digest,
            "bundleFileDigest": sha256(self.bundle_path.read_bytes()),
            "stateFileDigest": sha256(self.state_path.read_bytes()),
            "bundlePath": str(self.bundle_path), "statePath": str(self.state_path),
            "verifiedAt": NOW.isoformat(),
        })
        self.assertNotEqual(observation["bundleFileDigest"], verified.canonical_envelope_digest)
        for path in (self.bundle_path, self.state_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(self.private_path.exists())

    def test_actual_context_capture_reads_signer_without_provisioning_or_rewriting(self):
        before = self.public_path.read_bytes(), self.public_path.stat().st_ino, self.public_path.stat().st_mtime_ns
        with mock.patch.object(trust, "_load_private_key", side_effect=AssertionError("verification must not provision")):
            context = self.real_capture_context()
        self.assertEqual(context.public_key_der, self.public_der)
        self.assertEqual(context.schema_bytes, SCHEMA_PATH.read_bytes())
        self.assertIsNotNone(context.verified_at.tzinfo)
        self.assertEqual((self.public_path.read_bytes(), self.public_path.stat().st_ino, self.public_path.stat().st_mtime_ns), before)
        self.assertFalse(self.private_path.exists())
        self.assertEqual(self.snapshot(), (None, None))

    def test_missing_public_signer_cannot_create_a_private_key_or_trust_state(self):
        self.public_path.unlink()
        with mock.patch.object(trust, "_load_private_key", side_effect=AssertionError("verification must not provision")):
            with self.assertRaises(core.WebAuthnTrustError):
                self.real_capture_context()
        self.assertFalse(self.private_path.exists())
        self.assertFalse(self.public_path.exists())
        self.assertEqual(self.snapshot(), (None, None))

    def test_schema_signature_time_and_root_errors_do_not_mutate_installed_files(self):
        trust.write_trust_bundle(self.bundle())
        before = self.snapshot()
        bad_schema = self.bundle(2)
        bad_schema["unknown"] = True
        stale_signature = self.bundle(2)
        stale_signature["metadata"]["id"] = "changed-after-signing"
        invalid_root = self.bundle(2)
        invalid_root["roots"] = [{"id": "bad", "authenticatorClass": "hardware", "certificatePem": "not a certificate"}]
        cases = [
            (bad_schema, "schema validation failed"),
            (stale_signature, "signature verification failed"),
            (self.bundle(2, validUntil="2024-12-31T23:59:59Z"), "bundle is expired"),
            (self.sign(invalid_root), "root certificate is invalid"),
        ]
        for bundle, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(core.WebAuthnTrustError, diagnostic):
                    trust.write_trust_bundle(bundle)
                self.assertEqual(self.snapshot(), before)

    def test_stale_and_same_generation_fork_leave_both_files_unchanged(self):
        trust.write_trust_bundle(self.bundle(2))
        before = self.snapshot()
        for bundle, diagnostic in (
            (self.bundle(1), "bundle sequence is stale"),
            (self.bundle(2, id="same-generation-fork"), "content changed without advancing sequence"),
        ):
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaisesRegex(core.WebAuthnTrustError, diagnostic):
                    trust.write_trust_bundle(bundle)
                self.assertEqual(self.snapshot(), before)

    def test_same_candidate_retry_preserves_exact_state_bytes(self):
        bundle = self.bundle()
        first = trust.write_trust_bundle(bundle)
        before = self.snapshot()
        second = trust.write_trust_bundle(bundle)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(first["local_installation"], second["local_installation"])

    def test_state_rename_failure_leaves_prior_installation_and_allows_retry(self):
        trust.write_trust_bundle(self.bundle())
        before = self.snapshot()
        real_replace = os.replace
        def interrupted(source, target):
            if Path(target) == self.state_path:
                raise OSError("injected before state rename")
            return real_replace(source, target)
        with mock.patch.object(trust.os, "replace", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "before state rename"):
                trust.write_trust_bundle(self.bundle(2))
        self.assertEqual(self.snapshot(), before)
        trust.write_trust_bundle(self.bundle(2))
        self.assert_installed(self.bundle(2))

    def test_file_fsync_failure_precedes_any_target_rename(self):
        trust.write_trust_bundle(self.bundle())
        before = self.snapshot()
        real_fsync = os.fsync
        def interrupted(descriptor):
            if stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("injected file fsync failure")
            return real_fsync(descriptor)
        with mock.patch.object(trust.os, "fsync", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "file fsync failure"):
                trust.write_trust_bundle(self.bundle(2))
        self.assertEqual(self.snapshot(), before)

    def test_state_ahead_bundle_old_rejects_predecessor_and_fork_before_exact_retry(self):
        predecessor, candidate = self.bundle(), self.bundle(2)
        trust.write_trust_bundle(predecessor)
        old_bytes = self.bundle_path.read_bytes()
        real_replace = os.replace
        def interrupted(source, target):
            if Path(target) == self.bundle_path:
                raise OSError("injected before bundle rename")
            return real_replace(source, target)
        with mock.patch.object(trust.os, "replace", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "before bundle rename"):
                trust.write_trust_bundle(candidate)
        self.assertEqual(self.bundle_path.read_bytes(), old_bytes)
        state_ahead = self.state_path.read_bytes()
        self.assertEqual(json.loads(state_ahead)["bundle_digest"], self.verified(candidate).bundle_digest)
        for disallowed in (predecessor, self.bundle(2, id="fork")):
            with self.assertRaises(core.WebAuthnTrustError):
                trust.write_trust_bundle(disallowed)
            self.assertEqual(self.snapshot(), (old_bytes, state_ahead))
        with self.journal(self.publication(candidate, previous=self.verified(predecessor).bundle_digest)) as recorder:
            result = trust.reconcile_trust_publications(expected_publication_id="publication-local")
        self.assertTrue(result["reconciled"])
        self.assertEqual(self.state_path.read_bytes(), state_ahead)
        self.assert_installed(candidate)
        self.assertIn(("complete", "publication-local"), recorder.calls)

    def test_post_bundle_rename_directory_fsync_error_never_completes(self):
        bundle = self.bundle()
        real_replace, real_fsync = os.replace, os.fsync
        renamed = False
        def replace(source, target):
            nonlocal renamed
            result = real_replace(source, target)
            if Path(target) == self.bundle_path:
                renamed = True
            return result
        def fsync(descriptor):
            if renamed and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("injected after bundle rename")
            return real_fsync(descriptor)
        with self.journal(self.publication(bundle)) as recorder:
            with mock.patch.object(trust.os, "replace", side_effect=replace), mock.patch.object(trust.os, "fsync", side_effect=fsync):
                with self.assertRaisesRegex(OSError, "after bundle rename"):
                    trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
            self.assertEqual(len(recorder.errors), 1)
            # Bytes may already be visible; visibility is not a successful durable observation.
            self.assertEqual(self.bundle_path.read_bytes(), self.verified(bundle).installation_bytes)
            result = trust.reconcile_trust_publications()
        self.assertTrue(result["reconciled"])
        self.assertIn(("complete", "publication-local"), recorder.calls)

    def test_retry_repairs_ambiguous_state_directory_durability_before_completion(self):
        bundle = self.bundle()
        real_fsync, real_replace = os.fsync, os.replace
        fail_state_once = True
        durable_directories = []
        synced_files = set()
        renamed_state_file = None
        def replace(source, target):
            nonlocal renamed_state_file
            source_stat = Path(source).stat()
            result = real_replace(source, target)
            if Path(target) == self.state_path:
                renamed_state_file = (source_stat.st_dev, source_stat.st_ino)
            return result
        def fsync(descriptor):
            nonlocal fail_state_once
            descriptor_stat = os.fstat(descriptor)
            directory = None
            if stat.S_ISDIR(descriptor_stat.st_mode):
                for label, parent in (("state", self.state_path.parent), ("bundle", self.bundle_path.parent)):
                    if parent.exists():
                        parent_stat = parent.stat()
                        if (descriptor_stat.st_dev, descriptor_stat.st_ino) == (parent_stat.st_dev, parent_stat.st_ino):
                            directory = label
                if directory == "state" and fail_state_once:
                    fail_state_once = False
                    raise OSError("injected after state rename before directory durability")
            result = real_fsync(descriptor)
            if stat.S_ISREG(descriptor_stat.st_mode):
                synced_files.add((descriptor_stat.st_dev, descriptor_stat.st_ino))
            if directory is not None:
                durable_directories.append(directory)
            return result
        def complete_after_both_durable():
            self.assert_installed(bundle)
            self.assertIsNotNone(renamed_state_file)
            self.assertIn(renamed_state_file, synced_files)
            self.assertIn("state", durable_directories)
            self.assertIn("bundle", durable_directories)
        with self.journal(self.publication(bundle), complete_after_both_durable) as recorder:
            with mock.patch.object(trust.os, "fsync", side_effect=fsync), mock.patch.object(trust.os, "replace", side_effect=replace):
                with self.assertRaisesRegex(OSError, "after state rename before directory durability"):
                    trust.reconcile_trust_publications()
                self.assert_not_completed(recorder)
                self.assertFalse(self.bundle_path.exists())
                self.assertEqual(json.loads(self.state_path.read_bytes())["bundle_digest"], self.verified(bundle).bundle_digest)
                state_bytes = self.state_path.read_bytes()
                self.assertEqual(durable_directories, [])
                synced_files.clear()
                renamed_state_file = None
                result = trust.reconcile_trust_publications()
            self.assertTrue(result["reconciled"])
            self.assertEqual(self.state_path.read_bytes(), state_bytes)
            self.assertIn(("complete", "publication-local"), recorder.calls)

    def test_exact_bundle_readback_rejects_representation_change_without_completion(self):
        bundle = self.bundle()
        real_replace = os.replace
        def altered(source, target):
            result = real_replace(source, target)
            if Path(target) == self.bundle_path:
                # Same JSON and valid signature, different exact installed bytes.
                self.bundle_path.write_bytes(canonical(bundle))
            return result
        with self.journal(self.publication(bundle)) as recorder:
            with mock.patch.object(trust.os, "replace", side_effect=altered):
                with self.assertRaisesRegex(core.WebAuthnTrustError, "installation readback changed"):
                    trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
            self.assertEqual(len(recorder.errors), 1)

    def test_exact_state_readback_rejects_post_install_change_without_completion(self):
        bundle = self.bundle()
        real_replace = os.replace
        def altered(source, target):
            result = real_replace(source, target)
            if Path(target) == self.bundle_path:
                self.state_path.write_bytes(self.state_path.read_bytes() + b" ")
            return result
        with self.journal(self.publication(bundle)) as recorder:
            with mock.patch.object(trust.os, "replace", side_effect=altered):
                with self.assertRaisesRegex(core.WebAuthnTrustError, "installation readback changed"):
                    trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)

    def test_reconcile_reaches_completion_only_after_real_readback_and_withdrawal_checks(self):
        bundle = self.bundle()
        with self.journal(self.publication(bundle)) as recorder:
            result = trust.reconcile_trust_publications(expected_publication_id="publication-local")
        self.capture.assert_called_once_with()
        self.assertTrue(result["ok"])
        self.assertTrue(result["reconciled"])
        self.assertEqual(recorder.calls, ["pending", ("credential", "revoked-credential"), ("complete", "publication-local")])
        self.assertEqual(recorder.errors, [])

    def test_reconcile_journal_or_withdrawal_mismatch_precedes_installation(self):
        bundle = self.bundle()
        publication = self.publication(bundle)
        publication["sequence"] += 1
        with self.journal(publication) as recorder:
            with self.assertRaisesRegex(core.WebAuthnTrustError, "does not match its journal"):
                trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
        self.assertEqual(self.snapshot(), (None, None))
        with self.journal(self.publication(bundle)) as recorder:
            recorder.credentials["revoked-credential"]["revoked_at"] = None
            with self.assertRaisesRegex(core.WebAuthnTrustError, "active withdrawn credential"):
                trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
        self.assertEqual(self.snapshot(), (None, None))

    def test_reconcile_wrong_predecessor_does_not_mutate_files(self):
        trust.write_trust_bundle(self.bundle())
        before = self.snapshot()
        with self.journal(self.publication(self.bundle(2), previous="sha256:" + "f" * 64)) as recorder:
            with self.assertRaisesRegex(core.WebAuthnTrustError, "does not match publication history"):
                trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
        self.assertEqual(self.snapshot(), before)

    def test_completion_error_does_not_report_reconciled_and_retry_checks_installation(self):
        bundle = self.bundle()
        def failed_completion():
            self.assert_installed(bundle)
            raise OSError("injected completion failure")
        with self.journal(self.publication(bundle), failed_completion) as recorder:
            with self.assertRaisesRegex(OSError, "completion failure"):
                trust.reconcile_trust_publications()
            self.assert_not_completed(recorder)
            self.assertEqual(len(recorder.errors), 1)
        with self.journal(self.publication(bundle)) as recorder:
            self.assertTrue(trust.reconcile_trust_publications()["reconciled"])
            self.assertIn(("complete", "publication-local"), recorder.calls)


if __name__ == "__main__":
    unittest.main()
