#!/usr/bin/env python3
"""Purpose-key custody units, NOT native launch or authority acceptance.

Run as UID 0 in the isolated, network-disabled test container. Metadata, file
descriptors, seals, key parsing and ephemeral Ed25519 operations are real. Only
launch observations are synthetic. Exact process/configuration types below are
constructed without startup or a root-signed configuration; none of these tests
admits a reviewer, executes an authority operation or persists a receipt.

The runner must mount one public nonroot/mode-0400 synthetic fixture read-only
at CATCHPLATE_TEST_NONROOT_KEY_FIXTURE and name its canonical nonzero UID with
CATCHPLATE_TEST_NONROOT_KEY_FIXTURE_UID. Its preparer verifies the exact public
canary below; capless root deliberately cannot read that file. O_PATH observes
its real metadata without changing ownership or granting a DAC capability.
"""
from __future__ import annotations

import ast
import base64
from contextlib import ExitStack
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "test"
os.environ["CATCHPLATE_PRODUCTION_IMAGE"] = "0"

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catchplate import authority_launch_guard as launch
from catchplate import authority_native_jit_review_open_signers as subject
from catchplate import authority_service as service

AUTHOR = "CATCHPLATE_NATIVE_JIT_REVIEW_AUTHORIZER_KEY"
COMMIT = "CATCHPLATE_NATIVE_JIT_REVIEW_COMMIT_KEY"
FIELD = "nativeJitReviewOpeningPolicy"
ERROR = "Native review purpose signer is unavailable"
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
NONROOT_CANARY = b"catchplate synthetic nonroot signer fixture\n"


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())


def public_record(key):
    public = key.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"keyId": "sha256:" + hashlib.sha256(der).hexdigest(),
        "publicKeyBase64Url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}


class ReviewSignerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.geteuid() != 0:
            raise AssertionError("Real root-owned signer metadata tests require isolated UID 0")
        cls.nonroot_fixture = os.environ.get("CATCHPLATE_TEST_NONROOT_KEY_FIXTURE", "")
        if not cls.nonroot_fixture or not Path(cls.nonroot_fixture).is_absolute():
            raise AssertionError("An explicit read-only public nonroot fixture is required")
        uid = os.environ.get("CATCHPLATE_TEST_NONROOT_KEY_FIXTURE_UID", "")
        if not uid.isascii() or not uid.isdecimal() or len(uid) > 10 or str(int(uid)) != uid \
                or not 0 < int(uid) < 2**32 - 1:
            raise AssertionError("The preparer's canonical nonzero fixture UID is required")
        cls.nonroot_fixture_uid = int(uid)

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="native-review-signers-")))
        self.descriptors = set()
        self.addCleanup(self.close_descriptors)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(patch.dict(subject._OWNERS, {}, clear=True))
        self.assurance = {"trustMode": "external-production", "nativeStageZero": True}
        self.generation = {"sequence": 7, "digest": "sha256:" + "a" * 64,
            "stageZeroRequestDigest": "sha256:" + "b" * 64, "nested": {"retained": True}}
        self.retained = set()
        self.active = self.stack.enter_context(patch.object(launch, "require_active"))
        self.stack.enter_context(patch.object(launch, "launch_assurance", side_effect=lambda: self.assurance))
        self.stack.enter_context(patch.object(launch, "generation", side_effect=lambda: deepcopy(self.generation)))
        self.stack.enter_context(patch.object(launch, "retained_descriptors", side_effect=lambda: frozenset(self.retained)))
        self.keys = {role: Ed25519PrivateKey.generate() for role in ("planner", "executor", "generic", "root")}

    def close_descriptors(self):
        for descriptor in self.descriptors:
            os.close(descriptor)

    def keep(self, descriptor):
        self.descriptors.add(descriptor)
        return descriptor

    def file(self, raw=b"synthetic descriptor bytes", *, mode=0o400, access=os.O_RDONLY):
        path = self.directory / ("key-" + str(len(list(self.directory.iterdir()))))
        with path.open("xb") as handle:
            handle.write(raw)
        # Open before reducing the mode: the root container has no DAC override
        # capability, and these negative writable descriptors are deliberate.
        descriptor = self.keep(os.open(path, access | os.O_CLOEXEC))
        os.fchmod(descriptor, mode)
        return descriptor, path

    def memfd(self, raw, *, seals=SEALS, readonly=True):
        descriptor = os.memfd_create("synthetic-review-purpose-key", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            self.assertEqual(os.write(descriptor, raw), len(raw))
            os.fchmod(descriptor, 0o400)
            if seals:
                fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            if not readonly:
                return self.keep(descriptor)
            readonly_fd = os.open("/proc/self/fd/" + str(descriptor), os.O_RDONLY | os.O_CLOEXEC)
        except BaseException:
            os.close(descriptor)
            raise
        os.close(descriptor)
        return self.keep(readonly_fd)

    def process(self, role="planner", *, policy=True):
        payload = {"schema": service.CONFIG_SCHEMA, "unrelatedRootSelectedField": {"version": 1}}
        if policy:
            payload[FIELD] = {"authorizerKey": public_record(self.keys["planner"]),
                "commitOwnerKey": public_record(self.keys["executor"])}
        configuration = service.MeasuredConfiguration(payload,
            "sha256:" + hashlib.sha256(service._canonical(payload)).hexdigest(),
            self.keys["root"].public_key())
        process = object.__new__(service.AuthorityProcess)
        process.role_name = role
        process.process_mode = "policy-authority-" + role
        process.configuration = configuration
        process.signing_key = self.keys["generic"]
        process.writer_response_signing_key = self.keys["generic"]
        return process

    def prepare(self, role="planner", *, sealed=False, pem=False):
        process = self.process(role)
        key = self.keys[role]
        raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()) if pem else private_bytes(key)
        descriptor = self.memfd(raw) if sealed else self.file(raw)[0]
        environment = AUTHOR if role == "planner" else COMMIT
        for name in (AUTHOR, COMMIT):
            os.environ.pop(name + "_FD", None)
            os.environ.pop(name + "_PATH", None)
        os.environ[environment + "_FD"] = str(descriptor)
        self.retained.add(descriptor)
        return process, descriptor

    def admit(self, **kwargs):
        process, descriptor = self.prepare(**kwargs)
        subject.initialize(process)
        return process, descriptor, subject._OWNERS[process]

    def refused(self, operation):
        with self.assertRaises(subject.ReviewSignerError) as caught:
            operation()
        self.assertEqual(str(caught.exception), ERROR)
        return caught.exception

    def test_actual_single_link_root_readonly_metadata_is_exact(self):
        descriptor, _ = self.file()
        value = os.fstat(descriptor)
        self.assertEqual((value.st_uid, stat.S_IMODE(value.st_mode), value.st_nlink), (0, 0o400, 1))
        self.assertEqual(subject._metadata(descriptor), (value.st_dev, value.st_ino, value.st_mode,
            value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns))

    def test_actual_metadata_rejects_owner_mode_links_size_and_write_access(self):
        for case in ("owner", "mode", "links", "empty", "large", "write", "readwrite"):
            with self.subTest(case=case):
                if case == "owner":
                    descriptor = self.keep(os.open(self.nonroot_fixture,
                        os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC))
                    value = os.fstat(descriptor)
                    self.assertTrue(stat.S_ISREG(value.st_mode))
                    self.assertEqual((value.st_uid, stat.S_IMODE(value.st_mode), value.st_nlink,
                        value.st_size), (self.nonroot_fixture_uid, 0o400, 1, len(NONROOT_CANARY)))
                    with self.assertRaises(PermissionError):
                        self.keep(os.open(self.nonroot_fixture, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
                    self.refused(lambda: subject._metadata(descriptor))
                    continue
                raw = b"" if case == "empty" else b"x" * 65537 if case == "large" else b"key"
                access = os.O_WRONLY if case == "write" else os.O_RDWR if case == "readwrite" else os.O_RDONLY
                descriptor, path = self.file(raw, access=access)
                if case == "mode":
                    path.chmod(0o600)
                elif case == "links":
                    os.link(path, path.with_suffix(".other"))
                self.refused(lambda: subject._metadata(descriptor))
        descriptor, _ = self.file(b"x" * 65536)
        self.assertEqual(subject._metadata(descriptor)[6], 65536)

    def test_actual_directory_pipe_and_unlinked_ordinary_file_are_not_key_custody(self):
        directory = self.keep(os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY))
        read_fd, write_fd = os.pipe()
        self.keep(read_fd); self.keep(write_fd)
        for descriptor in (directory, read_fd):
            self.refused(lambda: subject._metadata(descriptor))
        descriptor, path = self.file()
        path.unlink()
        self.assertEqual(os.fstat(descriptor).st_nlink, 0)
        with self.assertRaises((OSError, subject.ReviewSignerError)):
            subject._metadata(descriptor)

    def test_actual_sealed_readonly_memfd_and_each_missing_seal(self):
        descriptor = self.memfd(private_bytes(self.keys["planner"]))
        value = subject._metadata(descriptor)
        self.assertEqual((value[3], stat.S_IMODE(value[2]), value[5]), (0, 0o400, 0))
        self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
        with self.assertRaises(OSError):
            os.write(descriptor, b"x")
        for seal in (fcntl.F_SEAL_SEAL, fcntl.F_SEAL_SHRINK, fcntl.F_SEAL_GROW, fcntl.F_SEAL_WRITE):
            with self.subTest(missing=seal):
                bad = self.memfd(b"synthetic", seals=SEALS & ~seal)
                self.refused(lambda: subject._metadata(bad))
        writable = self.memfd(b"synthetic", readonly=False)
        self.refused(lambda: subject._metadata(writable))

    def test_selector_requires_canonical_retained_descriptor_and_no_path(self):
        descriptor, _ = self.file()
        os.environ[AUTHOR + "_FD"] = str(descriptor)
        self.assertEqual(subject._descriptor(AUTHOR, {descriptor}), descriptor)
        self.refused(lambda: subject._descriptor(AUTHOR, set()))
        for text in ("", "0", "1", "2", "0" + str(descriptor), "+" + str(descriptor),
                " " + str(descriptor), str(descriptor) + "\n", "٣", "3.0", "99999999999"):
            with self.subTest(value=text):
                os.environ[AUTHOR + "_FD"] = text
                self.refused(lambda: subject._descriptor(AUTHOR, {descriptor}))
        os.environ[AUTHOR + "_FD"] = str(descriptor)
        for path in ("/synthetic/key", " "):
            os.environ[AUTHOR + "_PATH"] = path
            self.refused(lambda: subject._descriptor(AUTHOR, {descriptor}))

    def test_absent_policy_never_reads_a_key_or_admits_an_owner(self):
        process = self.process(policy=False)
        with patch.object(service, "_read_descriptor_original", side_effect=AssertionError("key read")):
            subject.initialize(process)
            self.assertNotIn(process, subject._OWNERS)
            self.active.assert_not_called()
            for name in (AUTHOR, COMMIT):
                for suffix in ("_FD", "_PATH"):
                    with patch.dict(os.environ, {name + suffix: "9"}):
                        self.refused(lambda: subject.initialize(process))
        self.refused(lambda: self.borrow_once(process))

    def test_wrong_role_extra_role_and_path_never_read_a_descriptor(self):
        with patch.object(service, "_read_descriptor_original", side_effect=AssertionError("key read")):
            wrong = self.process("verifier")
            subject.initialize(wrong)
            self.assertNotIn(wrong, subject._OWNERS)
            with patch.dict(os.environ, {AUTHOR + "_FD": "9"}):
                self.refused(lambda: subject.initialize(wrong))
            for role, other in (("planner", COMMIT), ("executor", AUTHOR)):
                process, _ = self.prepare(role)
                with patch.dict(os.environ, {other + "_FD": "9"}):
                    self.refused(lambda: subject.initialize(process))
                with patch.dict(os.environ, {other + "_PATH": "/synthetic/other"}):
                    self.refused(lambda: subject.initialize(process))
                own = AUTHOR if role == "planner" else COMMIT
                with patch.dict(os.environ, {own + "_PATH": "/synthetic/own"}):
                    self.refused(lambda: subject.initialize(process))

    def test_exact_process_and_configuration_types_are_required(self):
        self.refused(lambda: subject.initialize(object()))
        process = self.process()
        class Configuration(service.MeasuredConfiguration):
            pass
        process.configuration = Configuration(process.configuration.payload,
            process.configuration.digest, process.configuration.root_key)
        self.refused(lambda: subject.initialize(process))
        class Process(service.AuthorityProcess):
            pass
        child = object.__new__(Process)
        child.configuration = self.process().configuration
        self.refused(lambda: subject.initialize(child))

    def test_local_or_missing_native_assurance_refuses_before_key_read(self):
        process, _ = self.prepare()
        for assurance in ({}, {"trustMode": "trusted-host-local", "nativeStageZero": True},
                {"trustMode": "external-production", "nativeStageZero": False},
                {"trustMode": "tee-hardware", "nativeStageZero": 1}):
            with self.subTest(assurance=assurance):
                self.assurance = assurance
                with patch.object(service, "_read_descriptor_original", side_effect=AssertionError("key read")):
                    self.refused(lambda: subject.initialize(process))
                self.assertNotIn(process, subject._OWNERS)

    def test_actual_raw_and_pem_keys_for_each_role_and_delivery(self):
        for role, purpose in (("planner", "authorize"), ("executor", "committed-disclosure")):
            for sealed, pem in ((False, False), (False, True), (True, False), (True, True)):
                with self.subTest(role=role, sealed=sealed, pem=pem):
                    self.assurance["trustMode"] = "tee-hardware" if sealed else "external-production"
                    process, descriptor = self.prepare(role, sealed=sealed, pem=pem)
                    os.lseek(descriptor, 3, os.SEEK_SET)
                    subject.initialize(process)
                    self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 3)
                    with subject._borrow(process, purpose=purpose) as key:
                        message = b"synthetic custody unit, not an authority operation"
                        signature = key.sign(message)
                    self.keys[role].public_key().verify(signature, message)
                    with self.assertRaises(InvalidSignature):
                        self.keys["generic"].public_key().verify(signature, message)
                    self.assertFalse(subject._OWNERS[process].failed)

    def borrow_once(self, process, purpose="authorize"):
        with subject._borrow(process, purpose=purpose) as key:
            return key

    def test_no_generic_response_key_fallback_or_cross_purpose_borrow(self):
        for role, allowed in (("planner", "authorize"), ("executor", "committed-disclosure")):
            process, _ = self.prepare(role)
            environment = AUTHOR if role == "planner" else COMMIT
            os.environ.pop(environment + "_FD")
            self.refused(lambda: subject.initialize(process))
            self.assertNotIn(process, subject._OWNERS)
            self.refused(lambda: self.borrow_once(process, allowed))
            process, _, held = self.admit(role=role)
            for purpose in ("generic", "response", "receipt", "", "authorize" if role == "executor" else "committed-disclosure"):
                self.refused(lambda: self.borrow_once(process, purpose))
            self.assertFalse(held.failed)
            self.assertIs(self.borrow_once(process, allowed), held.private)

    def test_mismatched_policy_key_and_invalid_key_never_install_owner(self):
        process, descriptor = self.prepare()
        process.configuration.payload[FIELD]["authorizerKey"] = public_record(self.keys["generic"])
        self.refused(lambda: subject.initialize(process))
        self.assertNotIn(process, subject._OWNERS)
        process = self.process()
        descriptor, _ = self.file(b"not a private key")
        self.retained.add(descriptor)
        os.environ[AUTHOR + "_FD"] = str(descriptor)
        with self.assertRaises(service.AuthorityServiceError):
            subject.initialize(process)
        self.assertNotIn(process, subject._OWNERS)

    def test_duplicate_initialization_does_not_replace_existing_key(self):
        process, _, held = self.admit()
        self.refused(lambda: subject.initialize(process))
        self.assertIs(subject._OWNERS[process], held)
        self.assertIs(self.borrow_once(process), held.private)

    def test_full_configuration_nested_policy_and_digest_changes_poison(self):
        for case in ("unrelated", "policy", "digest", "configuration-object", "root"):
            with self.subTest(case=case):
                process, _, held = self.admit()
                configuration = process.configuration
                original_payload = deepcopy(configuration.payload)
                original_digest, original_root = configuration.digest, configuration.root_key
                if case == "unrelated":
                    configuration.payload["unrelatedRootSelectedField"]["version"] = 2
                elif case == "policy":
                    configuration.payload[FIELD]["commitOwnerKey"] = public_record(self.keys["generic"])
                elif case == "digest":
                    object.__setattr__(configuration, "digest", "sha256:" + "f" * 64)
                elif case == "root":
                    object.__setattr__(configuration, "root_key", self.keys["generic"].public_key())
                else:
                    process.configuration = service.MeasuredConfiguration(deepcopy(configuration.payload),
                        configuration.digest, configuration.root_key)
                self.refused(held.check)
                configuration.payload.clear(); configuration.payload.update(original_payload)
                object.__setattr__(configuration, "digest", original_digest)
                object.__setattr__(configuration, "root_key", original_root)
                process.configuration = configuration
                self.assertTrue(held.failed)
                self.refused(held.check)
                self.refused(lambda: self.borrow_once(process))

    def test_generation_role_process_mode_and_owner_changes_poison(self):
        for case in ("generation", "role", "mode", "owner"):
            with self.subTest(case=case):
                process, _, held = self.admit()
                if case == "generation":
                    self.generation["nested"]["retained"] = False
                elif case == "role":
                    process.role_name = "executor"
                elif case == "mode":
                    process.process_mode = "catchplate-control-plane"
                else:
                    subject._OWNERS.pop(process)
                self.refused(held.check)
                self.generation["nested"]["retained"] = True
                process.role_name, process.process_mode = "planner", "policy-authority-planner"
                subject._OWNERS[process] = held
                self.assertTrue(held.failed)
                self.refused(held.check)

    def test_descriptor_selector_retention_metadata_and_fd_identity_changes_poison(self):
        for case in ("selector", "path", "retention", "mode", "replacement"):
            with self.subTest(case=case):
                process, descriptor, held = self.admit()
                if case == "selector":
                    os.environ[AUTHOR + "_FD"] = "0" + str(descriptor)
                elif case == "path":
                    os.environ[AUTHOR + "_PATH"] = "/synthetic/path"
                elif case == "retention":
                    self.retained.remove(descriptor)
                elif case == "mode":
                    os.fchmod(descriptor, 0o600)
                else:
                    replacement, _ = self.file(private_bytes(self.keys["planner"]))
                    os.dup2(replacement, descriptor, inheritable=False)
                self.refused(held.check)
                os.environ[AUTHOR + "_FD"] = str(descriptor)
                os.environ.pop(AUTHOR + "_PATH", None)
                self.retained.add(descriptor)
                os.fchmod(descriptor, 0o400)
                self.assertTrue(held.failed)
                self.refused(held.check)

    def test_launch_revocation_and_assurance_loss_poison_even_after_restoration(self):
        for case in ("revocation", "local", "stagezero"):
            with self.subTest(case=case):
                process, _, held = self.admit()
                if case == "revocation":
                    self.active.side_effect = RuntimeError("synthetic launch revoked")
                elif case == "local":
                    self.assurance["trustMode"] = "trusted-host-local"
                else:
                    self.assurance["nativeStageZero"] = False
                self.refused(held.check)
                self.active.side_effect = None
                self.assurance.update(trustMode="external-production", nativeStageZero=True)
                self.refused(lambda: self.borrow_once(process))
                self.assertTrue(held.failed)

    def test_retained_process_identity_is_checked_without_mocking_os_identity(self):
        for name in ("pid", "uid", "gid"):
            with self.subTest(field=name):
                _, _, held = self.admit()
                original = getattr(held, name)
                setattr(held, name, original + 1)
                self.refused(held.check)
                setattr(held, name, original)
                self.refused(held.check)

    def test_borrow_exit_rechecks_state_and_does_not_recover_after_failure(self):
        process, _, held = self.admit()
        with self.assertRaisesRegex(subject.ReviewSignerError, "^" + ERROR + "$"):
            with subject._borrow(process, purpose="authorize"):
                self.generation["sequence"] += 1
        self.generation["sequence"] -= 1
        self.assertTrue(held.failed)
        self.refused(lambda: self.borrow_once(process))

    def test_borrower_exception_still_checks_custody_without_poisoning_valid_owner(self):
        process, _, held = self.admit()
        before = self.active.call_count
        with self.assertRaisesRegex(ValueError, "synthetic borrower failure"):
            with subject._borrow(process, purpose="authorize"):
                raise ValueError("synthetic borrower failure")
        self.assertEqual(self.active.call_count - before, 2)
        self.assertFalse(held.failed)
        self.assertIs(self.borrow_once(process), held.private)

    def test_first_held_check_failure_removes_owner_and_never_borrows(self):
        process, _ = self.prepare()
        self.active.side_effect = [None, RuntimeError("synthetic launch changed during initialization")]
        self.refused(lambda: subject.initialize(process))
        self.assertNotIn(process, subject._OWNERS)
        self.active.side_effect = None
        self.refused(lambda: self.borrow_once(process))

    def test_real_startup_hook_follows_configuration_custody_and_rbac_admission(self):
        tree = ast.parse((ROOT / "catchplate/authority_service.py").read_text())
        process = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AuthorityProcess")
        initializer = next(node for node in process.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        calls = [(node.func.value.id, node.func.attr, node.lineno) for node in ast.walk(initializer)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)]
        signer = [line for owner, method, line in calls
            if (owner, method) == ("authority_native_jit_review_open_signers", "initialize")]
        self.assertEqual(len(signer), 1)
        for owner, method in (("self", "_reject_wrong_credentials"),
                ("self", "_consume_attestation_release"), ("rbac_currentness", "initialize_authority")):
            lines = [line for found_owner, found_method, line in calls if (found_owner, found_method) == (owner, method)]
            self.assertEqual(len(lines), 1)
            self.assertLess(lines[0], signer[0])
        signer_source = (ROOT / "catchplate/authority_native_jit_review_open_signers.py").read_text()
        self.assertNotIn("process.signing_key", signer_source)
        self.assertNotIn("process.writer_response_signing_key", signer_source)


if __name__ == "__main__":
    unittest.main()
