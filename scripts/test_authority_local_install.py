#!/usr/bin/env python3
"""Pure contracts and real small Linux primitives, not a signed full installation.

No successful VerifiedArtifactPackage or filesystem-verity admission is mocked.
Complete installer success requires real independently issued package evidence
and a capable root-owned filesystem; these controls do not claim either.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority import local_install as cli
from catchplate import authority_artifact_spec as artifact
from catchplate import authority_local_install as install

PIN = "sha256:" + "1" * 64


def configuration():
    return dict(schema=install.CONFIGURATION_SCHEMA, destination=dict(path="/srv/authority-artifacts", device=1, inode=2),
        trustStateSha256=PIN, packageSha256=PIN, verificationReceiptSha256=PIN, keyId="local-installer",
        executorMeasurementDigest=PIN, requestId="install-1", transitionId="generation-1", bootIdDigest=PIN,
        issuedAtBoottimeNs=100, deadlineBoottimeNs=1000, issuedAtUnixNanos=200, expiresAtUnixNanos=2000)


def plan(*, local):
    # Untrusted schema data only: never a VerifiedArtifactPackage or receipt proof.
    steps = contract.LOCAL_PROVISIONING_STEPS if local else contract.ATOMIC_PROVISIONING_STEPS
    name = contract._generation_directory_name(0, PIN)
    value = dict(schema=contract.LOCAL_PROVISIONING_PLAN_SCHEMA if local else contract.PROVISIONING_PLAN_SCHEMA,
        packageDigest=PIN, artifactBundleDigest=PIN, generationDigest=PIN, generationSequence=0,
        minimumRollbackSequence=0, verificationReceiptDigest=PIN,
        sourceRoot=dict(fd=10, fdCustody="retained-by-local-installer-through-publish" if local else "retained-by-native-parent-through-publish",
            runtimePath="/srv/source", device=1, inode=2, generation=3, mountId=4, mode=0o555, uid=0, gid=0),
        destination=dict(root="/srv/authority-artifacts", generationsDirectory="generations", generationDirectory=name,
            stagingDirectory=".incoming/" + name, lockFile=".authority-generation.lock", terminalReceiptDirectory="receipts",
            ownerUid=0, ownerGid=0,
            directoryMode=contract.LOCAL_GENERATION_DIRECTORY_MODE if local else 0o750,
            renameFlags=["RENAME_NOREPLACE"]),
        entries=[dict(path="source.py", sourceSha256=PIN, size=3, mode=0o444, uid=0, gid=0,
            requireFsVerity=True, requireImmutable=True)],
        steps=[dict(ordinal=index, step=step) for index, step in enumerate(steps, 1)],
        activation=dict(performedByThisPlan=False, requiredSuccessorProtocol="stop-drain-reconcile-witness-activate-restart-v1",
            mutableCurrentSymlinkAllowed=False, runtimeMustOpenExactGenerationDirectory=True))
    value["localExecutor" if local else "nativeExecutor"] = dict(required=True, pythonExecutionAuthorized=local,
        requiredCapabilities=["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_LINUX_IMMUTABLE"],
        requiredSyscalls=["flock", "fsync", "openat2", "renameat2"],
        requiredFilesystemFeatures=["filesystem-generation", "fs-verity", "immutable-flag"])
    value["stepContractDigest"] = artifact.domain_digest(contract.PROVISIONING_STEP_CONTRACT_DOMAIN,
        artifact.canonical_json_bytes(value["steps"]))
    value["planId"] = artifact.domain_digest(contract.PROVISIONING_PLAN_DIGEST_DOMAIN, artifact.canonical_json_bytes(value))
    return value


class LocalInstallTests(unittest.TestCase):
    def test_prospective_setup_window_matches_shared_ceiling(self):
        self.assertEqual(install.MAX_SECONDS * 1_000_000_000, 5_400_000_000_000)
        for duration in (3_600_000_000_001, 5_400_000_000_000):
            value = configuration()
            value["deadlineBoottimeNs"] = value["issuedAtBoottimeNs"] + duration
            value["expiresAtUnixNanos"] = value["issuedAtUnixNanos"] + duration
            self.assertEqual(install.configuration(artifact.canonical_json_bytes(value)), value)
        for first, last in (("issuedAtBoottimeNs", "deadlineBoottimeNs"),
                            ("issuedAtUnixNanos", "expiresAtUnixNanos")):
            value = configuration(); value[last] = value[first] + 5_400_000_000_001
            with self.subTest(field=last), self.assertRaises(ValueError):
                install.configuration(artifact.canonical_json_bytes(value))

    def test_closed_independent_configuration_and_original_bounds(self):
        value = configuration()
        self.assertEqual(install.configuration(artifact.canonical_json_bytes(value)), value)
        for change in (dict(extra=True), dict(schema=contract.PROVISIONING_PLAN_SCHEMA),
                       dict(deadlineBoottimeNs=value["issuedAtBoottimeNs"]),
                       dict(expiresAtUnixNanos=value["issuedAtUnixNanos"] + (install.MAX_SECONDS + 1) * 10**9),
                       dict(destination=dict(path="/", device=1, inode=2)), dict(packageSha256="not-a-pin")):
            with self.subTest(change=change), self.assertRaises((ValueError, contract.ProvisioningContractError)):
                install.configuration(artifact.canonical_json_bytes(dict(value, **change)))

    def test_local_successor_does_not_relax_native_plan(self):
        for local in (False, True): contract.validate_provisioning_plan(plan(local=local))
        native = plan(local=False)
        native["nativeExecutor"]["pythonExecutionAuthorized"] = True
        with self.assertRaises(contract.ProvisioningContractError): contract.validate_provisioning_plan(native)
        selected = plan(local=True)
        selected["schema"] = contract.PROVISIONING_PLAN_SCHEMA
        with self.assertRaises(contract.ProvisioningContractError): contract.validate_provisioning_plan(selected)
        self.assertLess(contract.LOCAL_PROVISIONING_STEPS.index("renameat2-generation-noreplace"),
            contract.LOCAL_PROVISIONING_STEPS.index("set-published-generation-root-immutable"))
        self.assertNotIn("release-generation-lock", contract.LOCAL_PROVISIONING_STEPS)
        self.assertIn("release-generation-lock", contract.ATOMIC_PROVISIONING_STEPS)

    def test_no_verity_or_immutable_downgrade(self):
        for field in ("requireFsVerity", "requireImmutable"):
            value = plan(local=True); value["entries"][0][field] = False
            with self.assertRaises(contract.ProvisioningContractError): contract.validate_provisioning_plan(value)
        self.assertNotEqual(contract.provisioning_receipt_signature_message(dict(schema=contract.LOCAL_PROVISIONING_RECEIPT_SCHEMA,
            signatureBase64Url="", marker=PIN)), contract.provisioning_receipt_signature_message(
                dict(schema=contract.PROVISIONING_RECEIPT_SCHEMA, signatureBase64Url="", marker=PIN)))

    def test_local_generation_mode_is_versioned_and_native_mode_unchanged(self):
        self.assertEqual(contract.LOCAL_PROVISIONING_PLAN_SCHEMA,
            "catchplate.authorityTrustedHostLocalProvisioningPlan/v2")
        self.assertEqual(contract.LOCAL_GENERATION_DIRECTORY_MODE, 0o755)
        def rehash(value):
            value.pop("planId")
            value["planId"] = artifact.domain_digest(contract.PROVISIONING_PLAN_DIGEST_DOMAIN,
                artifact.canonical_json_bytes(value))
        for local, expected, swapped in ((False, 0o750, 0o755), (True, 0o755, 0o750)):
            value = plan(local=local)
            self.assertEqual(value["destination"]["directoryMode"], expected)
            contract.validate_provisioning_plan(value)
            value["destination"]["directoryMode"] = swapped
            rehash(value)
            with self.assertRaises(contract.ProvisioningContractError): contract.validate_provisioning_plan(value)
        old = plan(local=True)
        old["schema"] = "catchplate.authorityTrustedHostLocalProvisioningPlan/v1"
        old["destination"]["directoryMode"] = 0o750
        rehash(old)
        with self.assertRaises(contract.ProvisioningContractError): contract.validate_provisioning_plan(old)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0,
        "actual root-to-65532 DAC test in disposable Linux container")
    def test_actual_finalized_generation_exec_import_preserves_private_denial(self):
        # Real installer mode helper and real dropped-UID exec/import only: no
        # signature, fs-verity, immutable flag, mount or full-install admission.
        with tempfile.TemporaryDirectory(prefix="authority-install-dac-") as directory:
            base = Path(directory); base.chmod(0o755)
            generation = base / "generation"
            source, runtime = generation / "source", generation / "runtime"
            binary = runtime / "bin"
            directories = (generation, source, runtime, binary)
            for path in directories: path.mkdir(mode=0o700)
            executable = binary / "python3"
            shutil.copyfile(sys.executable, executable); executable.chmod(0o555)
            module = source / "public_fixture.py"
            module.write_text("VALUE = 'public-source-read'\n"); module.chmod(0o444)
            configuration = generation / "configuration.json"
            configuration.write_bytes(b"synthetic-private-configuration"); configuration.chmod(0o400)
            private, old_mode = base / "private-installation", base / "old-generation"
            private.mkdir(mode=0o700); old_mode.mkdir(mode=0o750)
            private_leaf, old_leaf = private / "receipt", old_mode / "public.py"
            for path in (private_leaf, old_leaf): path.write_bytes(b"synthetic"); path.chmod(0o444)
            leaves = (executable, module, configuration, private_leaf, old_leaf)
            def identity(path):
                info = path.stat()
                return (info.st_dev, info.st_ino, info.st_size, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
            originals = {path: identity(path) for path in leaves}
            for path in reversed(directories):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    for invalid in (0o750, 0o777, True):
                        with self.assertRaises(ValueError): install._set_generation_directory_mode(fd, invalid)
                    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o700)
                    install._set_generation_directory_mode(fd, contract.LOCAL_GENERATION_DIRECTORY_MODE)
                    info = os.fstat(fd)
                    self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid), (0o755, 0, 0))
                    with self.assertRaises(ValueError): install._set_generation_directory_mode(fd, 0o755)
                finally: os.close(fd)
            self.assertEqual({path: identity(path) for path in leaves}, originals)
            probe = """import os, sys
assert os.getresuid() == os.getresgid() == (65532, 65532, 65532)
assert os.getgroups() == []
os.chdir(sys.argv[1])
sys.path.insert(0, os.getcwd())
import public_fixture
assert public_fixture.VALUE == 'public-source-read'
for path in sys.argv[2:]:
    try:
        with open(path, 'rb'):
            raise AssertionError('private path became readable')
    except PermissionError:
        pass
print('UID65532_EXEC_IMPORT_AND_PRIVATE_DENIAL=1')
"""
            result = subprocess.run([str(executable), "-I", "-B", "-S", "-c", probe,
                str(source), str(configuration), str(private_leaf), str(old_leaf)],
                user=65532, group=65532, extra_groups=(), cwd="/", env={"PATH": os.defpath},
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "UID65532_EXEC_IMPORT_AND_PRIVATE_DENIAL=1\n")
            self.assertEqual(result.stderr, "")
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(old_mode.stat().st_mode), 0o750)
            self.assertEqual({path: identity(path) for path in leaves}, originals)

    def test_public_cli_is_fixed_and_all_handles_distinct(self):
        argv = ["--configuration-fd", "3", "--configuration-sha256", PIN, "--package-fd", "4", "--package-sha256", PIN,
            "--verification-fd", "5", "--verification-sha256", PIN, "--source-root-fd", "6", "--signing-key-fd", "7"]
        self.assertEqual(cli.arguments(argv)["source_root_fd"], 6)
        for changed in (argv + ["--command", "anything"], [*argv[:13], "5", *argv[14:]],
                        [argv[0], "03", *argv[2:]], [*argv[:-1], "-1"]):
            with self.assertRaises(ValueError): cli.arguments(changed)

    @unittest.skipUnless(sys.platform == "linux" and os.uname().machine == "x86_64", "actual Linux x86_64 primitives")
    def test_actual_openat2_refuses_symlink_and_escape(self):
        with tempfile.TemporaryDirectory(prefix="authority-install-") as directory:
            Path(directory, "source").write_bytes(b"public")
            Path(directory, "alias").symlink_to("source")
            root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fd = install._open_beneath(root, "source", os.O_RDONLY | os.O_CLOEXEC)
                try: self.assertEqual(os.read(fd, 16), b"public")
                finally: os.close(fd)
                with self.assertRaises(OSError): install._open_beneath(root, "alias", os.O_RDONLY)
                with self.assertRaises(contract.ProvisioningContractError): install._open_beneath(root, "../source", os.O_RDONLY)
            finally: os.close(root)

    @unittest.skipUnless(sys.platform == "linux", "actual Linux renameat2")
    def test_actual_no_replace_keeps_prior_bytes(self):
        with tempfile.TemporaryDirectory(prefix="authority-install-") as directory:
            Path(directory, "incoming").write_bytes(b"new")
            Path(directory, "existing").write_bytes(b"old")
            root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileExistsError): install._rename(root, "incoming", root, "existing")
                self.assertEqual(Path(directory, "existing").read_bytes(), b"old")
                self.assertEqual(Path(directory, "incoming").read_bytes(), b"new")
                install._rename(root, "incoming", root, "published")
                self.assertEqual(Path(directory, "published").read_bytes(), b"new")
            finally: os.close(root)

    @unittest.skipUnless(sys.platform == "linux", "actual Linux ioctl refusal")
    def test_unsupported_kernel_descriptor_never_becomes_verity_evidence(self):
        read, write = os.pipe()
        try:
            with self.assertRaises(OSError): install._verity(read)
            with self.assertRaises(OSError): install._generation(read)
        finally:
            os.close(read); os.close(write)

    @unittest.skipUnless(sys.platform == "linux", "actual per-descriptor frozen-state check")
    def test_actual_writable_descriptor_cannot_inherit_a_readonly_ancestor_claim(self):
        with tempfile.TemporaryDirectory(prefix="authority-install-frozen-") as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with self.assertRaises((OSError, ValueError)):
                    install._frozen(fd)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
