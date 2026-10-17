#!/usr/bin/env python3
"""UNRUN immutable-custody controls; genuine synthetic certificates/signatures.

Protected-FD controls require the real isolated root process contract and skip
otherwise. No database, guest launch or pilot-duration claim is made. Only
clock samples and explicit negative faults are doubled; admission remains real.
"""
import ast
import base64
import copy
import inspect
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from catchplate import authority_local_configuration as local
from catchplate import authority_local_database_credentials as credentials
from scripts.test_authority_local_configuration import SEED, fixture, sealed


class PreparationSourceControls(unittest.TestCase):
    def test_real_admission_is_once_at_transfer_and_never_a_caller_verdict(self):
        tree = ast.parse(inspect.getsource(local.IssuedConfigurationCustody))
        methods = {node.name: node for node in tree.body[0].body if isinstance(node, ast.FunctionDef)}
        take_calls = [ast.unparse(node.func) for node in ast.walk(methods["_take"])
            if isinstance(node, ast.Call)]
        self.assertEqual(take_calls.count("self._admit"), 1)
        self.assertLess(inspect.getsource(local.IssuedConfigurationCustody._take).index("self._admit()"),
            inspect.getsource(local.IssuedConfigurationCustody._take).index("self.check()"))
        admission = inspect.getsource(local.IssuedConfigurationCustody._admit)
        self.assertIn("prepared = prepare(self._raw", admission)
        self.assertIn('issued["payload"] == prepared["payload"]', admission)
        self.assertIn('Ed25519PublicKey.from_public_bytes(prepared["rootPublic"]).verify(', admission)
        self.assertIn("self._admitted is None and self._admitted_pin is None", admission)
        checking = inspect.getsource(local.IssuedConfigurationCustody.check)
        self.assertNotIn("prepare(", checking)
        self.assertNotIn("document(", checking)
        self.assertNotIn(".verify(", checking)
        self.assertEqual(checking.count("io.read_public(self._fd, io.MAX_PUBLIC) == self._raw"), 2)
        self.assertEqual(checking.count("io._input(self._fd, io.MAX_PUBLIC) == self._identity"), 2)
        self.assertEqual(checking.count("os.getpid() == self._pid"), 2)
        self.assertEqual(checking.count("launcher._boot_identity_digest() == self._boot"), 2)
        self.assertEqual(tuple(inspect.signature(local.IssuedConfigurationCustody._take).parameters), ("issuer",))
        with self.assertRaises(TypeError):
            local.IssuedConfigurationCustody()


class IssuedPreparationControls(unittest.TestCase):
    def setUp(self):
        if (os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
                or not sys.flags.isolated or not sys.flags.dont_write_bytecode):
            self.skipTest("protected originals require actual isolated root -I -B; not simulated")
        self.inputs = set()
        self.addCleanup(self._close_inputs)

    def _close_inputs(self):
        while self.inputs:
            os.close(self.inputs.pop())

    def _issuer(self, *, selected=None, regular=False):
        if selected is None:
            selected, _, _ = fixture()
        raw = local.spec.canonical_json_bytes(selected)
        path = None
        if regular:
            directory = tempfile.TemporaryDirectory(prefix="issued-configuration-control-")
            self.addCleanup(directory.cleanup)
            path = Path(directory.name) / "approval.json"
            path.write_bytes(raw)
            path.chmod(0o400)
            public = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            public = sealed(raw)
        private = sealed(SEED)
        self.inputs.update((public, private))
        issuer = local.LocalConfigurationIssuer(approval_fd=public,
            approval_sha256=local.sha(raw), signing_key_fd=private)
        return issuer, selected, public, private, path

    def _take(self, issuer):
        with local._owning():
            owner = issuer.take_public_custody()
        self.addCleanup(owner.close)
        return owner

    def test_one_full_genuine_preparation_then_live_checks_without_repeated_crypto(self):
        issuer, selected, public, private, _ = self._issuer()
        issued = issuer.issue()
        with mock.patch.object(local, "prepare", wraps=local.prepare) as prepared, \
                mock.patch.object(credentials, "issuance", wraps=credentials.issuance) as authenticated:
            owner = self._take(issuer)
        self.assertEqual(prepared.call_count, 1)
        self.assertEqual(authenticated.call_count, len(local.SERVICE_ROLES))
        self.assertEqual({call.kwargs["purpose"] for call in authenticated.call_args_list}, local.SERVICE_ROLES)
        for fd in (public, private):
            os.close(fd)
            self.inputs.remove(fd)
        with mock.patch.object(local, "prepare", side_effect=AssertionError("repeated full preparation")), \
                mock.patch.object(credentials, "issuance", side_effect=AssertionError("repeated certificates")), \
                mock.patch.object(local, "document", side_effect=AssertionError("repeated parse")), \
                mock.patch.object(local.io, "signing_key", side_effect=AssertionError("private key access")):
            owner.check()
            self.assertEqual(owner.service_original(), issued)
            self.assertEqual(owner.approval_original(), local.spec.canonical_json_bytes(selected))
            self.assertEqual(owner.verifier_issuance_original(),
                selected["databaseIssuanceOriginals"]["verifier"].encode("ascii"))
        self.assertFalse(hasattr(owner, "_prepared") or hasattr(owner, "_key_fd"))
        self.assertFalse(any(getattr(owner, name) is issuer for name in owner.__slots__))

    def test_retained_preparation_contains_only_immutable_originals_and_scalars(self):
        issuer, _, _, _, _ = self._issuer()
        issuer.issue()
        graphs = []
        actual = local.prepare

        def capture(*args, **kwargs):
            value = actual(*args, **kwargs)
            graphs.append(value)
            return value

        with mock.patch.object(local, "prepare", side_effect=capture):
            owner = self._take(issuer)
        original = owner.service_original(), owner.verifier_issuance_original()

        def immutable(value):
            self.assertIn(type(value), (tuple, bytes, str, int))
            if type(value) is tuple:
                for child in value:
                    immutable(child)

        immutable(owner._admitted)
        self.assertIs(owner._admitted, owner._admitted_pin)
        graphs[0]["selected"]["databaseIssuanceOriginals"].clear()
        graphs[0]["payload"].clear()
        graphs[0]["deadline"] = graphs[0]["epochLimit"] = 1
        issuer._prepared.clear()  # No issuer graph remains a custody dependency.
        self.assertEqual((owner.service_original(), owner.verifier_issuance_original()), original)
        with self.assertRaises(ValueError):
            owner._admit()

    def test_initial_service_payload_and_real_signature_must_match_before_retention(self):
        selected, _, _ = fixture()
        for field in ("payload", "signature"):
            issuer, _, _, _, _ = self._issuer(selected=selected)
            issued = local.document(issuer.issue(), local.MAX_CONFIGURATION)
            if field == "payload":
                issued[field]["launchNonceDigest"] = "sha256:" + "0" * 64
            else:
                issued[field] = local.spec.strict_base64url_encode(bytes(64))
            issuer._issued_original = local.spec.canonical_json_bytes(issued)
            with self.subTest(field=field), self.assertRaises((ValueError, InvalidSignature)):
                self._take(issuer)
            self.assertTrue(issuer._public_custody_attempted)
            with self.assertRaises(ValueError):
                self._take(issuer)

    def test_original_certificate_signature_and_generation_bounds_are_not_skipped(self):
        selected, _, _ = fixture()
        bad = copy.deepcopy(selected)
        original = local.document(bad["databaseIssuanceOriginals"]["verifier"].encode("ascii"), local.io.MAX_PUBLIC)
        pem = original["certificateOriginal"]
        der = bytearray(base64.b64decode("".join(pem.strip().splitlines()[1:-1]), validate=True))
        der[-1] ^= 1  # Parseable real certificate with one corrupted signature bit.
        encoded = base64.b64encode(der).decode("ascii")
        original["certificateOriginal"] = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
            encoded[offset:offset + 64] for offset in range(0, len(encoded), 64)) + "\n-----END CERTIFICATE-----\n"
        bad["databaseIssuanceOriginals"]["verifier"] = local.spec.canonical_json_bytes(original).decode("ascii")
        with self.assertRaises((ValueError, InvalidSignature)):
            self._issuer(selected=bad)
        bad = copy.deepcopy(selected)
        bad["generation"]["validUntil"] = bad["generation"]["validFrom"]
        with self.assertRaises(ValueError):
            self._issuer(selected=bad)

    def test_both_samples_preserve_exact_expiry_and_monotone_clock_bounds(self):
        issuer, selected, _, _, _ = self._issuer()
        issuer.issue()
        owner = self._take(issuer)
        boot, epoch = owner._last_boot, owner._last_unix
        end_boot, end_epoch = selected["deadlineBoottimeNs"], selected["expiresAtUnixNanos"]
        choices = (([end_boot, end_boot], [epoch, epoch]),
            ([boot, end_boot], [epoch, epoch]), ([boot - 1, boot], [epoch, epoch]),
            ([boot + 1, boot], [epoch, epoch]), ([boot, boot], [end_epoch, end_epoch]),
            ([boot, boot], [epoch, end_epoch]), ([boot, boot], [epoch - 1, epoch]),
            ([boot, boot], [epoch + 1, epoch]))
        for boots, epochs in choices:
            with self.subTest(boots=boots, epochs=epochs), \
                    mock.patch.object(local.io, "_clock", side_effect=boots), \
                    mock.patch.object(local.time, "time_ns", side_effect=epochs), self.assertRaises(ValueError):
                owner.check()
        with mock.patch.object(local.launcher, "_boot_identity_digest", return_value="sha256:" + "0" * 64), \
                self.assertRaises(ValueError):
            owner.check()
        with mock.patch.object(local.os, "getpid", return_value=owner._pid + 1), self.assertRaises(ValueError):
            owner.check()
        with mock.patch.object(local.io, "_clock", return_value=end_boot), \
                mock.patch.object(local.time, "time_ns", return_value=end_epoch):
            owner.close()  # Expiry never prevents safe release of the owned duplicate.

    def test_modified_file_bytes_and_substituted_in_memory_originals_refuse(self):
        issuer, _, _, _, path = self._issuer(regular=True)
        issuer.issue()
        owner = self._take(issuer)
        for field in ("_raw", "_issued", "_admitted"):
            original = getattr(owner, field)
            changed = tuple(list(original)) if type(original) is tuple else original[:-1] + b"x"
            setattr(owner, field, changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                owner.check()
            setattr(owner, field, original)
        owner.check()
        path.chmod(0o600)
        with path.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b"x")
        path.chmod(0o400)
        with self.assertRaises(ValueError):
            owner.check()
        owner.close()

    def test_failed_partial_transfer_closes_only_duplicate_and_never_retries(self):
        issuer, _, public, private, _ = self._issuer()
        issuer.issue()
        duplicated = []
        actual = local.fcntl.fcntl

        def observe(fd, operation, *args):
            result = actual(fd, operation, *args)
            if operation == local.fcntl.F_DUPFD_CLOEXEC:
                duplicated.append(result)
            return result

        with mock.patch.object(local.fcntl, "fcntl", side_effect=observe), \
                mock.patch.object(local, "prepare", side_effect=ValueError("injected admission refusal")), \
                self.assertRaises(ValueError):
            self._take(issuer)
        self.assertEqual(len(duplicated), 1)
        with self.assertRaises(OSError):
            os.fstat(duplicated[0])
        os.fstat(public)
        os.fstat(private)
        self.assertTrue(issuer._public_custody_attempted)
        with self.assertRaises(ValueError):
            self._take(issuer)


if __name__ == "__main__":
    unittest.main()
