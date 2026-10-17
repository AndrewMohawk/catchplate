#!/usr/bin/env python3
"""Closed data contracts and real FD/exchange primitives, not package admission.

There is no synthetic successful VerifiedArtifactPackage or mocked successful
signature/installation validator. Full commit needs genuine assembled package,
installer and persistent witness evidence on a verity-capable filesystem.
"""
from __future__ import annotations

import ast
import copy
import fcntl
import os
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.authority import local_trust_commit as cli
from scripts.test_authority_local_install import plan as untrusted_plan
from scripts.test_authority_local_trust import fixture as initial_fixture
from catchplate import authority_local_trust_commit as local

PIN = "sha256:" + "1" * 64
NOW = "2026-10-01T00:00:03Z"


def selected():
    return dict(schema=local.SCHEMA, purpose=local.PURPOSE,
        destination=dict(path="/srv/local-artifacts", device=1, inode=2), witnessDirectory=dict(device=1, inode=3),
        priorTrustSha256=PIN, packageSha256=PIN, verificationReceiptSha256=PIN, planSha256=PIN,
        provisioningReceiptSha256=PIN, terminalStateSha256=PIN, witnessHeadSha256=PIN,
        requestId="install-0", transitionId="first-generation", bootIdDigest=PIN,
        issuedAtBoottimeNs=100, deadlineBoottimeNs=200, issuedAtUnixNanos=1000, expiresAtUnixNanos=2000)


def chain():
    # Unauthenticated schema data, never a provisioning-receipt signature.
    plan = untrusted_plan(local=True)
    identity = dict(device=1, inode=2, generation=3, mode=plan["destination"]["directoryMode"], uid=0, gid=0)
    raw = local.spec.canonical_json_bytes(dict(completedAt="2026-10-01T00:00:02Z", generationDirectoryIdentity=identity))
    source = local.spec.domain_digest("catchplate.authorityProvisioningSourceIdentity/v1", local.spec.canonical_json_bytes(plan["sourceRoot"]))
    first = dict(schema=local.contract.PROVISIONING_STATE_SCHEMA, stateId=PIN, revision=0, status="Prepared",
        requestId="install-0", transitionId="first-generation", packageDigest=plan["packageDigest"],
        generationDigest=plan["generationDigest"], planDigest=local.contract.provisioning_plan_digest(plan),
        sourceRootIdentityDigest=source, previousStateDigest=None, preparedAt="2026-10-01T00:00:00Z",
        publishedAt=None, terminalAt=None, publishedIdentityDigest=None, terminalReceiptDigest=None,
        terminalReceiptBytesBase64Url=None, abortReasonDigest=None)
    states = []
    for index in range(3):
        value = dict(first if index == 0 else states[-1])
        value.pop("recordDigest", None)
        if index:
            value.update(revision=index, status=("Published", "Receipted")[index-1], previousStateDigest=states[-1]["recordDigest"],
                publishedAt="2026-10-01T00:00:01Z", publishedIdentityDigest=local.spec.domain_digest(
                    "catchplate.authorityProvisionedGenerationIdentity/v1", local.spec.canonical_json_bytes(identity)))
        if index == 2:
            value.update(terminalAt=NOW, terminalReceiptDigest=local.spec.domain_digest("catchplate.authorityExactTerminalReceiptBytes/v1", raw),
                terminalReceiptBytesBase64Url=local.spec.strict_base64url_encode(raw))
        value["recordDigest"] = local.spec.domain_digest(local.contract.PROVISIONING_STATE_DIGEST_DOMAIN, local.spec.canonical_json_bytes(value))
        states.append(value)
    return states, plan, raw


class TrustCommitTests(unittest.TestCase):
    def test_closed_explicit_approval_original_bounds_and_no_generic_path(self):
        value = selected()
        self.assertEqual(local.approval(local.spec.canonical_json_bytes(value)), value)
        for change in (dict(extra=True), dict(purpose="update-any-generation"), dict(priorTrustSha256=None),
                       dict(destination=dict(path="/", device=1, inode=2)), dict(deadlineBoottimeNs=100),
                       dict(expiresAtUnixNanos=1001 + local.MAX_OPERATION_NS)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                local.approval(local.spec.canonical_json_bytes(dict(value, **change)))

    def test_only_independently_supplied_empty_genesis_not_reset_or_retry(self):
        trust = initial_fixture()["trust"]
        self.assertEqual(local.initial_state(local.spec.canonical_json_bytes(trust)), trust)
        for change in (dict(currentGenerationSequence=0), dict(acceptedEvidenceDigests=[PIN]),
                       dict(acceptedGenerationDigests=[PIN]), dict(acceptedPackageDigests=[PIN]),
                       dict(revokedKeyIds=["revoked-root"]), dict(minimumRollbackSequence=1)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                local.initial_state(local.spec.canonical_json_bytes(dict(trust, **change)))

    def test_literal_terminal_chain_schema_not_receipt_authentication(self):
        states, plan, raw = chain()
        kwargs = dict(plan=plan, receipt_raw=raw, request_id="install-0", transition_id="first-generation", validation_time=NOW)
        local.terminal_chain(states, **kwargs)
        for changed in (states[:2], list(reversed(states))):
            with self.assertRaises(ValueError): local.terminal_chain(changed, **kwargs)
        with self.assertRaises(local.contract.ProvisioningContractError):
            local.terminal_chain([states[0], states[1], dict(states[2], requestId="other")], **kwargs)
        with self.assertRaises(ValueError): local.terminal_chain(states, **dict(kwargs, receipt_raw=raw + b"\n"))
        with self.assertRaises(ValueError): local.terminal_chain(states, **dict(kwargs, validation_time="2026-10-01T00:00:02Z"))

    def test_actual_consumer_rechecks_and_retention_precede_exchange(self):
        with self.assertRaises(ValueError):
            local._next_state(initial_fixture()["trust"], {"disposition": "Successor"}, validation_time=NOW)
        with self.assertRaises(ValueError): local.LocalArtifactTrustCommit(None)
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == "LocalArtifactTrustCommit")
        methods = {row.name: row for row in owner.body if isinstance(row, ast.FunctionDef)}
        run = ast.unparse(methods["run"])
        self.assertLess(run.index("self._lock("), run.index("self._authenticate("))
        self.assertLess(run.index("self._authenticate("), run.index("self._publish("))
        publish = ast.unparse(methods["_publish"])
        self.assertLess(publish.index("spec.verify_signed_artifact_package("), publish.index("_exchange("))
        self.assertLess(publish.index("contract.verify_provisioning_receipt("), publish.index("_exchange("))
        self.assertLess(publish.index("self.exchange_attempted = True"), publish.index("_exchange("))
        self.assertLess(publish.index("_exchange("), publish.index("self.committed = True"))
        self.assertIn("self.check()", publish[publish.index("_exchange("):])
        self.assertNotIn("unlink", ast.unparse(owner))
        self.assertNotIn("signing_key", ast.unparse(owner))

    def test_fixed_cli_borrows_six_distinct_descriptors_no_keys_or_commands(self):
        args = [flag for index, name in enumerate(("approval", "trust", "package", "verification"), 3)
                for flag in ("--"+name+"-fd", str(index), "--"+name+"-sha256", PIN)]
        args += ["--destination-fd", "7", "--witness-directory-fd", "8"]
        self.assertEqual(cli.arguments(args)["witness_directory_fd"], 8)
        for wrong in (args+["--reset"], [args[0], "03", *args[2:]], args[:-1]+["3"], args[:-1]+["-1"]):
            with self.assertRaises(ValueError): cli.arguments(wrong)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "root-owned Linux directory modes")
    def test_actual_generation_directory_uses_plan_mode_not_private_destination_mode(self):
        mode = untrusted_plan(local=True)["destination"]["directoryMode"]
        with tempfile.TemporaryDirectory(prefix="local-trust-generation-mode-") as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                local.install._set_generation_directory_mode(fd, mode)
                local._directory(fd, mode)
                with self.assertRaises(ValueError): local._directory(fd, 0o750)
                os.fchmod(fd, 0o750)
                local._directory(fd, 0o750)
                with self.assertRaises(ValueError): local._directory(fd, mode)
            finally: os.close(fd)
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == "LocalArtifactTrustCommit")
        methods = {row.name: row for row in owner.body if isinstance(row, ast.FunctionDef)}
        self.assertIn("self._subdirectory(generations, name, plan['destination']['directoryMode'])",
            ast.unparse(methods["_authenticate"]))
        self.assertIn("_directory(child, self._plan['destination']['directoryMode'])",
            ast.unparse(methods["_installation"]))

    @unittest.skipUnless(sys.platform == "linux", "Linux atomic exchange")
    def test_real_exchange_retains_displaced_original_and_open_fd_identities(self):
        with tempfile.TemporaryDirectory(prefix="local-trust-exchange-") as directory:
            old, new = Path(directory, local.install.TRUST_NAME), Path(directory, local.PENDING_NAME)
            old.write_bytes(b"old-public-original"); new.write_bytes(b"new-public-original")
            old.chmod(0o400); new.chmod(0o400)
            root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            before_old, before_new = os.open(old, os.O_RDONLY), os.open(new, os.O_RDONLY)
            try:
                with self.assertRaises(FileExistsError): os.open(local.PENDING_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root)
                local._exchange(root); os.fsync(root)
                self.assertEqual(old.read_bytes(), b"new-public-original")
                self.assertEqual(new.read_bytes(), b"old-public-original")
                self.assertEqual(old.stat().st_ino, os.fstat(before_new).st_ino)
                self.assertEqual(new.stat().st_ino, os.fstat(before_old).st_ino)
                self.assertEqual(os.pread(before_old, 100, 0), b"old-public-original")
                self.assertEqual(os.pread(before_new, 100, 0), b"new-public-original")
            finally:
                os.close(before_new); os.close(before_old); os.close(root)

    @unittest.skipUnless(sys.platform == "linux", "Linux atomic exchange")
    def test_real_missing_prior_refuses_without_creating_or_destroying_state(self):
        with tempfile.TemporaryDirectory(prefix="local-trust-exchange-refusal-") as directory:
            pending = Path(directory, local.PENDING_NAME); pending.write_bytes(b"partial-new-state")
            root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileNotFoundError): local._exchange(root)
                self.assertFalse(Path(directory, local.install.TRUST_NAME).exists())
                self.assertEqual(pending.read_bytes(), b"partial-new-state")
            finally: os.close(root)

    @unittest.skipUnless(sys.platform == "linux", "Linux ioctl refusal")
    def test_real_unsupported_descriptor_is_not_verity_evidence(self):
        read, write = os.pipe()
        try:
            with self.assertRaises(OSError): local._measure_verity(read)
        finally: os.close(read); os.close(write)

    @unittest.skipUnless(os.getuid() == 0 and sys.flags.isolated and sys.flags.dont_write_bytecode, "actual root isolated protected FD admission")
    def test_real_partial_acquisition_retains_owner_and_leaves_borrowed_fds_open(self):
        with tempfile.TemporaryDirectory(prefix="local-trust-owner-") as directory:
            dirs = [Path(directory, name) for name in ("destination", "witness")]
            for path in dirs: path.mkdir(mode=0o700)
            dirs[0].chmod(0o750)
            raws = [local.spec.canonical_json_bytes(selected()), b"{}", b'{"package":"not-evidence"}', b'{"receipt":"not-evidence"}']
            fds, owner = [], None
            try:
                for raw in raws:
                    fd = os.memfd_create("public-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING); fds.append(fd)
                    os.write(fd, raw); os.fchmod(fd, 0o400); fcntl.fcntl(fd, fcntl.F_ADD_SEALS, local.io.SEALS)
                fds += [os.open(path, os.O_RDONLY | os.O_DIRECTORY) for path in dirs]
                with self.assertRaises(local.LocalArtifactTrustCommitError) as caught:
                    local.LocalArtifactTrustCommit.open(approval_fd=fds[0], approval_sha256=local.sha(raws[0]),
                        trust_fd=fds[1], trust_sha256=local.sha(raws[1]), package_fd=fds[2], package_sha256=local.sha(raws[2]),
                        verification_fd=fds[3], verification_sha256=local.sha(raws[3]), destination_fd=fds[4], witness_directory_fd=fds[5])
                owner = caught.exception.owner
                self.assertEqual(len(owner._fds), 6)
                self.assertFalse(owner.exchange_attempted)
                owner.close()
                self.assertTrue(owner._closed)
                for fd in fds: os.fstat(fd)
                self.assertEqual(list(dirs[0].iterdir()), [])
            finally:
                if owner is not None: owner.close()
                for fd in reversed(fds): os.close(fd)

    def test_real_mappingproxy_at_shared_digest_and_installer_consumer_boundaries(self):
        # This is a serialization-boundary probe, NOT an accepted artifact. The
        # downstream spy always refuses; no successful validator is replaced.
        value = {"untrusted": [1, 2]}
        readonly = MappingProxyType(dict(value))  # Actual VerifiedArtifactPackage outer-wrapper type.
        with self.assertRaises(local.spec.ArtifactContractError): local.spec.canonical_json_bytes(readonly)
        observed = []
        class RefusedAtBoundary(RuntimeError): pass
        def refuse(argument):
            self.assertIs(type(argument), dict)
            observed.append(local.spec.canonical_json_bytes(argument))
            raise RefusedAtBoundary()
        with patch.object(local.contract, "signed_artifact_package_digest", side_effect=refuse):
            with self.assertRaises(RefusedAtBoundary): local.contract.signed_package_digest(readonly)
        self.assertEqual(observed, [local.spec.canonical_json_bytes(value)])
        tree = ast.parse(Path(local.install.__file__).read_text())
        calls = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and isinstance(row.func, ast.Attribute)
            and row.func.attr == "verify_signed_artifact_package" and row.args
            and "self.verified.package" in ast.unparse(row.args[0])]
        self.assertEqual([ast.unparse(row.args[0]) for row in calls], ["dict(self.verified.package)"])
        # Apply that exact fixed builtin to the real wrapper and actual JSON codec.
        self.assertEqual(local.spec.canonical_json_bytes(dict(readonly)), local.spec.canonical_json_bytes(value))


if __name__ == "__main__":
    unittest.main()
