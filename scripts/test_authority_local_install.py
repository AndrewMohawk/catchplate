#!/usr/bin/env python3
"""Pure contracts and real small Linux primitives, not a signed full installation.

No successful VerifiedArtifactPackage or filesystem-verity admission is mocked.
Complete installer success requires real independently issued package evidence
and a capable root-owned filesystem; these controls do not claim either.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority import local_install as cli
from serverware import authority_artifact_spec as artifact
from serverware import authority_local_install as install

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
            ownerUid=0, ownerGid=0, directoryMode=0o750, renameFlags=["RENAME_NOREPLACE"]),
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
    def test_closed_independent_configuration_and_original_bounds(self):
        value = configuration()
        self.assertEqual(install.configuration(artifact.canonical_json_bytes(value)), value)
        for change in (dict(extra=True), dict(schema=contract.PROVISIONING_PLAN_SCHEMA),
                       dict(deadlineBoottimeNs=value["issuedAtBoottimeNs"]),
                       dict(expiresAtUnixNanos=value["issuedAtUnixNanos"] + 3601 * 10**9),
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
