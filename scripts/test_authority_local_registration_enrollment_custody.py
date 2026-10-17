#!/usr/bin/env python3
"""Owner-custody controls with real synthetic signatures and protected FDs.

The runtime controls require isolated root -I -B, the explicit sandbox flag,
a disposable /run, and CAP_CHOWN only to create the exact test directory. They
never adopt an existing directory. Native FD/process checks and all admission,
signing and independent consumer functions are genuine, not success doubles.
Only clock faults and the deliberately exhausted recheck ledger are injected.
These tests prove neither a deployed enrollment nor pilot startup performance.
"""
import ast
import copy
import hashlib
import inspect
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catchplate import authority_local_registration_enrollment as local
from scripts.test_authority_local_configuration import sealed
from scripts.test_authority_local_registration_enrollment import fixture, work


ERRORS = (ValueError, InvalidSignature)
SANDBOX = "CATCHPLATE_TEST_LOCAL_REGISTRATION_ENROLLMENT_SANDBOX"


def _resign_fractional_configuration(selected, root):
    """Real test-key signatures on the existing finite-float Service6 domain."""
    selected = copy.deepcopy(selected)
    signed = local.document(selected["serviceConfigurationOriginal"].encode("ascii"), local.io.MAX_PUBLIC)
    payload = signed["payload"]
    payload["roles"]["planner"]["requestTimeoutSeconds"] = 0.5
    # Unused configuration is nevertheless captured and signed verbatim; it
    # confers no policy or authority and must not normalize negative zero.
    payload["syntheticFiniteScalarControl"] = [-0.0, 1.25]
    digest = local.configuration.capability.plan._frame(
        local.configuration.CONFIG_SCHEMA, (local.canonical(payload),), work())
    signed["signature"] = local.spec.strict_base64url_encode(
        root.sign(local.local.signature_message("authority-service", payload)))
    source_raw = local.canonical(signed)
    selected["serviceConfigurationOriginal"] = source_raw.decode("ascii")
    selected["serviceConfigurationSha256"] = local.sha(source_raw)
    binding = selected["generation"]["configurationPayloadBindings"][0]
    binding.update(fileDigest=local.sha(source_raw), payloadDigest=digest)
    cohort = local.document(selected["cohortOriginal"].encode("ascii"), local.cohort.MAX_BYTES)
    for envelope in (*cohort["payload"]["receipts"], cohort):
        envelope["payload"]["configurationDigest"] = digest
        envelope["signature"] = local.spec.strict_base64url_encode(root.sign(
            local.cohort._domain_digest(envelope["schema"],
                local.canonical(envelope["payload"])).encode("ascii")))
    cohort_raw = local.canonical(cohort)
    selected["cohortOriginal"], selected["cohortSha256"] = cohort_raw.decode("ascii"), local.sha(cohort_raw)
    return selected


class EnrollmentCustodySourceControls(unittest.TestCase):
    def test_only_constructor_authenticates_and_recheck_stage_is_not_removed(self):
        owner = local.LocalRegistrationEnrollment
        tree = ast.parse(inspect.getsource(owner))
        methods = {node.name: node for node in tree.body[0].body if isinstance(node, ast.FunctionDef)}
        preparation_calls = [(name, node) for name, method in methods.items()
            for node in ast.walk(method) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "prepare"]
        self.assertEqual([name for name, _ in preparation_calls], ["__init__"])
        self.assertEqual(tuple(inspect.signature(owner).parameters),
            ("approval_fd", "approval_sha256", "signing_key_fd", "context_directory_fd"))
        self.assertEqual(local.WORK_STAGES,
            ("acquire-public-inputs", "recheck-public-inputs", *local.OUTPUTS))
        self.assertIn('take("recheck-public-inputs")', inspect.getsource(owner.issue))
        self.assertIn("root.verify(", inspect.getsource(local.prepare))
        self.assertIn("cohort._verify_cohort_against_scope(", inspect.getsource(local.prepare))
        composition = inspect.getsource(local._compose)
        for actual in ("current._produce_enrollment_on_work(", "grant._produce_on_work(",
                       "module._produce_enrollment_on_work(", "bootstrap._produce_v4_on_work("):
            self.assertIn(actual, composition)
        self.assertNotIn("prepare(", inspect.getsource(owner.check))
        self.assertNotIn(".verify(", inspect.getsource(owner.check))
        # This optimization must not change either original authentication or
        # the independent five-output signing/consumer composition. Pin their
        # actual base bodies, not an invented successful receipt. Literal
        # source hashing is independent of Python 3.11/3.12 AST field changes.
        for function, digest in ((local.prepare,
                "d6ac3bdc73bb8e54a84c8feee9cce2d3756979127a45b81590e7d6d1b1fa113c"),
                (local._compose, "b7864826637e359178db1c6d0e374463e48aa9a19fd57909e1fb2146bb86a64b")):
            self.assertEqual(hashlib.sha256(inspect.getsource(function).encode()).hexdigest(), digest)


class EnrollmentCustodyControls(unittest.TestCase):
    def setUp(self):
        if (os.environ.get(SANDBOX) != "1" or os.getresuid() != (0, 0, 0)
                or os.getresgid() != (0, 0, 0) or not sys.flags.isolated
                or not sys.flags.dont_write_bytecode):
            self.skipTest("requires explicit disposable-/run root -I -B sandbox with CAP_CHOWN")
        environment = mock.patch.dict(os.environ, {"CATCHPLATE_RELEASE_CHANNEL": "dev",
            "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap"})
        environment.start()
        self.addCleanup(environment.stop)
        self.inputs = set()
        self.owners = []
        self.parent = Path("/run/catchplate")
        self.created_parent = not self.parent.exists()
        if self.created_parent:
            self.parent.mkdir(mode=0o755)
        self.directory = Path(local.DIRECTORY)
        self.assertFalse(self.directory.exists(), "must not adopt a pre-existing context directory")
        self.directory.mkdir(mode=0o750)
        self.addCleanup(self._cleanup)
        os.chown(self.directory, 0, 65532, follow_symlinks=False)
        self.directory.chmod(0o750)
        info = self.directory.stat()
        self.directory_identity = info.st_dev, info.st_ino
        self.directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.inputs.add(self.directory_fd)
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 65532, 0o750))

    def _cleanup(self):
        for owner in reversed(self.owners):
            owner.close()
        while self.inputs:
            os.close(self.inputs.pop())
        info = self.directory.stat()
        self.assertEqual((info.st_dev, info.st_ino), self.directory_identity)
        self.directory.rmdir()  # Only the exact empty task-created directory.
        if self.created_parent:
            self.parent.rmdir()

    def _owner(self, *, selected=None, root=None, private_seed=None, regular=False):
        if selected is None:
            selected, root = fixture()
        selected = copy.deepcopy(selected)
        selected["contextDirectory"] = dict(path=local.DIRECTORY,
            device=self.directory_identity[0], inode=self.directory_identity[1])
        raw = local.canonical(selected)
        path = None
        if regular:
            temporary = tempfile.TemporaryDirectory(prefix="registration-custody-")
            self.addCleanup(temporary.cleanup)
            path = Path(temporary.name) / "approval.json"
            path.write_bytes(raw)
            path.chmod(0o400)
            public_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        else:
            public_fd = sealed(raw)
        if private_seed is None:
            private_seed = root.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption())
        key_fd = sealed(private_seed)
        self.inputs.update((public_fd, key_fd))
        owner = local.LocalRegistrationEnrollment(approval_fd=public_fd,
            approval_sha256=local.sha(raw), signing_key_fd=key_fd,
            context_directory_fd=self.directory_fd)
        self.owners.append(owner)
        return owner, selected, root, path

    def test_one_actual_authentication_then_original_window_five_output_issuance(self):
        selected, root = fixture()
        with mock.patch.object(local, "prepare", wraps=local.prepare) as prepared, \
                mock.patch.object(local.cohort, "_verify_cohort_against_scope",
                    wraps=local.cohort._verify_cohort_against_scope) as cohort_verified:
            owner, selected, root, _ = self._owner(selected=selected, root=root)
        self.assertEqual((prepared.call_count, cohort_verified.call_count), (1, 1))
        with mock.patch.object(local, "prepare", side_effect=AssertionError("repeated public admission")):
            owner.check()
            raw = owner.issue()
            owner.check()
        bundle = local.document(raw, local.io.MAX_PUBLIC)
        self.assertEqual(bundle["approvalSha256"], local.sha(local.canonical(selected)))
        self.assertEqual((bundle["deadlineBoottimeNs"], bundle["expiresAtUnixNanos"]),
            (selected["deadlineBoottimeNs"], selected["expiresAtUnixNanos"]))
        self.assertEqual(set(bundle["originals"]), set(local.OUTPUTS))
        for name, text in bundle["originals"].items():
            self.assertEqual(bundle["sha256"][name], local.sha(text.encode("ascii")))
        admitted = local.bootstrap._admit_on_work(
            bootstrap_bytes=bundle["originals"]["controlPlaneBootstrap"].encode("ascii"),
            runtime_root_public_key=root.public_key(),
            expected_configuration_digest=bundle["configurationDigest"], work=work())
        self.assertEqual(admitted.execution.current_root_enrollment_bytes,
            bundle["originals"]["currentRootEnrollment"].encode("ascii"))
        self.assertEqual(admitted.finalization.grant_enrollment_bytes,
            bundle["originals"]["grantEnrollment"].encode("ascii"))
        self.assertEqual(admitted.execution.context_directory, self.directory_identity)
        self.assertEqual(owner.work_plan.next_stage, len(local.WORK_STAGES))
        self.assertFalse(bundle["databaseObserved"] or bundle["hardwareCeremonyPerformed"] or bundle["grantsIssued"])
        with self.assertRaises(ValueError):
            owner.issue()
        owner.close()
        for fd in (owner.fd, owner.key_fd, self.directory_fd):
            os.fstat(fd)  # Borrowed descriptors remain caller-owned after close.

    def test_initial_service_and_cohort_signatures_are_genuinely_required(self):
        selected, root = fixture()
        for name in ("serviceConfiguration", "cohort"):
            changed = copy.deepcopy(selected)
            signed = local.document(changed[name + "Original"].encode("ascii"), local.io.MAX_PUBLIC)
            signed["signature"] = local.spec.strict_base64url_encode(bytes(64))
            raw = local.canonical(signed)
            changed[name + "Original"], changed[name + "Sha256"] = raw.decode("ascii"), local.sha(raw)
            with self.subTest(original=name), self.assertRaises(ERRORS):
                self._owner(selected=changed, root=root)

    def test_mutated_context_and_key_objects_refuse_before_private_access(self):
        selected, root = fixture()
        mutations = {
            "selected": lambda ctx: ctx["selected"].update(databaseId="substituted"),
            "payload": lambda ctx: ctx["payload"]["roles"]["planner"].update(requestTimeoutSeconds=2),
            "generation": lambda ctx: ctx["generation"].update(sequence=1),
            "runtime": lambda ctx: ctx["runtime"]["roles"]["planner"].update(measurementDigest="sha256:" + "0" * 64),
            "vector": lambda ctx: ctx["vector"]["primaryRoots"][0].update(leafCount=1),
            "chain": lambda ctx: next(iter(ctx["chain"].values())).update(publicKeyBase64Url="substituted"),
            "deadline": lambda ctx: ctx.update(deadline=ctx["deadline"] + 1),
            "epoch": lambda ctx: ctx.update(epochLimit=ctx["epochLimit"] + 1),
        }
        for name in ("root", "planner", "evidence"):
            mutations[name] = lambda ctx, name=name: ctx.update({name:
                local.Ed25519PublicKey.from_public_bytes(ctx[name].public_bytes(local.Encoding.Raw, local.PublicFormat.Raw))})
        for name, mutate in mutations.items():
            owner, _, _, _ = self._owner(selected=selected, root=root)
            mutate(owner.context)
            with self.subTest(field=name), \
                    mock.patch.object(local.io, "signing_key", side_effect=AssertionError("private key reached")) as private, \
                    self.assertRaises(ValueError):
                owner.issue()
            self.assertEqual(private.call_count, 0)

    def test_recheck_budget_is_real_and_exhaustion_precedes_private_access(self):
        owner, _, _, _ = self._owner()
        tiny = local._ValidationWork(local.QueryReadValidationLimits(max_input_bytes=1, max_json_nodes=1))
        actual_take = owner.work_plan.take

        def take(name):
            actual = actual_take(name)  # Preserve the actual one-use schedule.
            return tiny if name == "recheck-public-inputs" else actual

        with mock.patch.object(owner.work_plan, "take", side_effect=take), \
                mock.patch.object(local.io, "signing_key", side_effect=AssertionError("private key reached")) as private, \
                self.assertRaises(local.accounting.QueryReadWorkError):
            owner.issue()
        self.assertEqual(private.call_count, 0)
        self.assertEqual(owner.work_plan.next_stage, 2)
        with self.assertRaises(ValueError):
            owner.issue()

    def test_wrong_sealed_signer_and_literal_fd_substitution_refuse(self):
        selected, root = fixture()
        owner, _, _, _ = self._owner(selected=selected, root=root, private_seed=b"W" * 32)
        with self.assertRaises(ValueError):
            owner.issue()
        self.assertEqual(owner.work_plan.next_stage, 2)
        for which in ("fd", "key_fd"):
            owner, _, _, _ = self._owner(selected=selected, root=root)
            original = owner.raw if which == "fd" else root.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption())
            replacement = sealed(original)
            self.inputs.add(replacement)
            os.dup2(replacement, getattr(owner, which), inheritable=False)
            with self.subTest(descriptor=which), self.assertRaises(ValueError):
                owner.check()  # Identical bytes on a different inode still refuse.

    def test_modified_approval_bytes_and_named_directory_replacement_refuse(self):
        owner, _, _, _ = self._owner()
        original = owner.raw
        owner.raw = original[:-1] + b"x"
        with self.assertRaises(ValueError):
            owner.check()
        owner.raw = original
        owner.check()
        owner, _, _, path = self._owner(regular=True)
        path.chmod(0o600)
        with path.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b"x")
        path.chmod(0o400)
        with self.assertRaises(ValueError):
            owner.check()
        owner, _, _, _ = self._owner()
        previous = self.directory.with_name("registration-contexts-control-original")
        self.assertFalse(previous.exists())
        self.directory.rename(previous)
        try:
            self.directory.mkdir(mode=0o750)
            os.chown(self.directory, 0, 65532, follow_symlinks=False)
            self.directory.chmod(0o750)
            with self.assertRaises(ValueError):
                owner.check()
        finally:
            self.directory.rmdir()
            previous.rename(self.directory)

    def test_process_environment_boot_thread_and_actual_fork_are_not_reusable(self):
        owner, _, _, _ = self._owner()
        with mock.patch.dict(os.environ, {"SYNTHETIC_CUSTODY_CONTEXT_CHANGED": "1"}), self.assertRaises(ValueError):
            owner.check()
        with mock.patch.object(local.local.launcher, "_boot_identity_digest", return_value="sha256:" + "0" * 64), \
                self.assertRaises(ValueError):
            owner.check()
        errors = []

        def other_thread():
            try:
                owner.check()
            except ValueError:
                errors.append("refused")

        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["refused"])
        child = os.fork()
        if child == 0:
            try:
                owner.check()
            except ValueError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(1)
        waited, status = os.waitpid(child, 0)
        self.assertEqual((waited, os.waitstatus_to_exitcode(status)), (child, 0))
        owner.check()

    def test_original_expiry_rollback_and_expiry_during_real_signer_refuse(self):
        selected, root = fixture()
        for clock_name, first, second in (("boot", "end", "end"), ("boot", "same", "end"),
                ("boot", "back", "same"), ("boot", "next", "same"),
                ("epoch", "end", "end"), ("epoch", "same", "end"),
                ("epoch", "back", "same"), ("epoch", "next", "same")):
            owner, _, _, _ = self._owner(selected=selected, root=root)
            now = owner.last_boot if clock_name == "boot" else owner.last_unix
            end = selected["deadlineBoottimeNs" if clock_name == "boot" else "expiresAtUnixNanos"]
            values = {"same": now, "back": now - 1, "next": now + 1, "end": end}
            target, attribute = (local.io, "_clock") if clock_name == "boot" else (local.time, "time_ns")
            with self.subTest(clock=clock_name, samples=(first, second)), \
                    mock.patch.object(target, attribute, side_effect=[values[first], values[second]]), \
                    self.assertRaises(ValueError):
                owner.check()
        owner, _, _, _ = self._owner(selected=selected, root=root)
        actual = local.current._produce_enrollment_on_work
        expired = False
        epoch = owner.last_unix

        def sign_then_expire(**kwargs):
            nonlocal expired
            result = actual(**kwargs)
            expired = True
            return result

        with mock.patch.object(local.time, "time_ns", side_effect=lambda:
                selected["expiresAtUnixNanos"] if expired else epoch), \
                mock.patch.object(local.current, "_produce_enrollment_on_work", side_effect=sign_then_expire) as first, \
                mock.patch.object(local.grant, "_produce_on_work", wraps=local.grant._produce_on_work) as next_stage, \
                self.assertRaises(ValueError):
            owner.issue()
        self.assertEqual((first.call_count, next_stage.call_count), (1, 0))

    def test_original_finite_fractional_configuration_and_negative_zero_survive(self):
        selected, root = fixture()
        selected = _resign_fractional_configuration(selected, root)
        owner, _, _, _ = self._owner(selected=selected, root=root)
        self.assertEqual(owner.context["payload"]["roles"]["planner"]["requestTimeoutSeconds"], 0.5)
        zero = owner.context["payload"]["syntheticFiniteScalarControl"][0]
        self.assertIs(type(zero), float)
        self.assertEqual(math.copysign(1, zero), -1)
        with mock.patch.object(local, "prepare", side_effect=AssertionError("repeated admission")):
            bundle = local.document(owner.issue(), local.io.MAX_PUBLIC)
        self.assertEqual(bundle["configurationDigest"], owner.context["configurationDigest"])
        self.assertIn(b'[-0.0,1.25]', local.canonical(owner.context["payload"]))


if __name__ == "__main__":
    unittest.main()
