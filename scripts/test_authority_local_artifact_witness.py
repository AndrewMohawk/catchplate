#!/usr/bin/env python3
"""Real local chain IO with synthetic signed cores, not package admission."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_artifact_witness as cli
from catchplate import authority_local_artifact_witness as local

DIGEST = "sha256:" + "1" * 64
SEED = b"w" * 32


def _time(delta=0):
    return datetime.fromtimestamp(time.time() + delta, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fixture():
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = dict(keyId="synthetic-local-witness", purposes=["trust-document", "witness-checkpoint"],
        publicKeyBase64Url=local.spec.strict_base64url_encode(public), keyFileSha256=local.sha(public),
        authorizationDigest=DIGEST, notBefore=_time(-3600), notAfter=_time(86400))
    trust = dict(schema=local.spec.TRUST_STATE_SCHEMA, currentGenerationSequence=-1,
        currentGenerationDigest=None, currentPackageDigest=None, minimumRollbackSequence=0,
        acceptedPackageDigests=[], acceptedGenerationDigests=[], acceptedEvidenceDigests=[],
        rootKeys=[key], currentKeys=[], revokedKeyIds=[], witness=dict(identity="synthetic-local-log",
        keyId=key["keyId"], publicKeyBase64Url=key["publicKeyBase64Url"], keyFileSha256=key["keyFileSha256"],
        authorizationDigest=DIGEST, currentSequence=-1, currentCheckpointDigest=DIGEST,
        currentRootDigest="sha256:" + "2" * 64, currentTreeSize=0))
    core = dict(schema=local.spec.GENERATION_STATEMENT_SCHEMA, sequence=0, generationId="synthetic-generation-0",
        predecessorDigest=None, minimumRollbackSequence=0, validFrom=_time(-60), validUntil=_time(3600),
        stageZeroContract=local.spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA, migrationReceiptDigests=[],
        roleManifestDigests=[], configurationDigests=[], configurationPayloadBindings=[],
        trustMode=dict(mode="trusted-host-local", hardwareBacked=False, externalWitnessRequired=False,
                       teeQuoteRequired=False, imaAppraisalRequired=False))
    for name in ("artifactBundleDigest", "operationManifestDigest", "stageZeroDigest", "roleSetDigest",
                 "snapshotReceiptDigest", "closureReceiptDigest", "provenanceStatementDigest", "sourceTreeDigest",
                 "ociManifestDigest", "keyAuthorizationsDigest", "keyRevocationsDigest"):
        core[name] = DIGEST
    return core, trust, private


def signed_generation(core, trust, private):
    witness = trust["witness"]
    digest = local.spec.domain_digest(local.spec.GENERATION_CORE_DIGEST_DOMAIN, local.spec.canonical_json_bytes(core))
    leaf = local.spec.domain_digest(local.spec.WITNESS_LEAF_DIGEST_DOMAIN, digest.encode("ascii"))
    size = witness["currentTreeSize"] + 1
    payload = dict(schema="catchplate.authorityWitnessCheckpointPayload/v1", identity=witness["identity"],
        sequence=core["sequence"], previousCheckpointDigest=witness["currentCheckpointDigest"],
        previousRootDigest=witness["currentRootDigest"], previousTreeSize=witness["currentTreeSize"], treeSize=size,
        generationCoreDigest=digest, leafDigest=leaf,
        rootDigest=local.spec.domain_digest(local.spec.WITNESS_CHAIN_ROOT_DOMAIN,
            witness["currentRootDigest"].encode("ascii"), str(size).encode("ascii"), leaf.encode("ascii")),
        issuedAt=_time(), coLocated=True, hardwareBacked=False)
    signature = private.sign(local.spec.domain_digest(local.spec.WITNESS_CHECKPOINT_SIGNATURE_DOMAIN,
        local.spec.canonical_json_bytes(payload)).encode("ascii"))
    return dict(core, witnessCheckpoint=dict(schema="catchplate.signedAuthorityWitnessCheckpoint/v1",
        payload=payload, signerKeyId=witness["keyId"], algorithm="Ed25519",
        signatureBase64Url=local.spec.strict_base64url_encode(signature)))


def _sealed(raw):
    fd = os.memfd_create("synthetic-witness-input", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        if os.write(fd, raw) != len(raw):
            raise RuntimeError("fixture short write")
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, local.io.SEALS)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_owner(directory, core, trust, *, action="initialize-and-append", expected=None, seed=SEED, v2=False):
    rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    info = os.fstat(rootfd)
    core_raw, trust_raw = map(local.spec.canonical_json_bytes, (core, trust))
    boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    approved = dict(schema=local.APPROVAL_SCHEMA, action=action, directory=dict(device=info.st_dev, inode=info.st_ino),
        trustSha256=local.sha(trust_raw), coreSha256=local.sha(core_raw), expectedHeadSha256=expected,
        signerKeyId=trust["witness"]["keyId"], bootIdDigest=local._boot(), issuedAtBoottimeNs=boot,
        deadlineBoottimeNs=boot+30_000_000_000, issuedAtUnixNanos=unix, expiresAtUnixNanos=unix+30_000_000_000)
    if v2:
        from catchplate.authority_local_trust import EMPTY_WITNESS_CONVENTION
        approved.update(schema=local.APPROVAL_SCHEMA_V2, emptyWitnessConvention=EMPTY_WITNESS_CONVENTION)
    raw = local.spec.canonical_json_bytes(approved)
    return local.LocalArtifactWitness.open(approval_fd=_sealed(raw), approval_sha256=local.sha(raw),
        trust_fd=_sealed(trust_raw), trust_sha256=local.sha(trust_raw), core_fd=_sealed(core_raw),
        core_sha256=local.sha(core_raw), directory_fd=rootfd, signing_key_fd=_sealed(seed))


def successor(directory, trust):
    # This test explicitly supplies a separately updated trust input. The issuer
    # itself never manufactures/commits package trust or accepts a package.
    raw = (Path(directory) / local._name(0)).read_bytes()
    generation = local.document(raw)
    trust = copy.deepcopy(trust)
    digest = local.spec.generation_statement_digest(generation)
    trust.update(currentGenerationSequence=0, currentGenerationDigest=digest, currentPackageDigest=DIGEST,
                 acceptedPackageDigests=[DIGEST], acceptedGenerationDigests=[digest])
    checkpoint = generation["witnessCheckpoint"]
    trust["witness"].update(currentSequence=0, currentCheckpointDigest=local.spec.witness_checkpoint_digest(checkpoint),
        currentRootDigest=checkpoint["payload"]["rootDigest"], currentTreeSize=1)
    core = {key: value for key, value in generation.items() if key != "witnessCheckpoint"}
    core.update(sequence=1, generationId="synthetic-generation-1", predecessorDigest=digest)
    return core, trust, local.sha((Path(directory) / local.HEAD_NAME).read_bytes())


class WitnessContractTests(unittest.TestCase):
    def test_v2_convention_is_explicit_and_initial_only(self):
        from catchplate.authority_local_trust import EMPTY_WITNESS_CONVENTION
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        value = dict(schema=local.APPROVAL_SCHEMA_V2, action="initialize-and-append", directory=dict(device=1,inode=2),
            trustSha256=DIGEST, coreSha256=DIGEST, expectedHeadSha256=None, signerKeyId="synthetic-witness",
            bootIdDigest=DIGEST, issuedAtBoottimeNs=boot, deadlineBoottimeNs=boot+10**9,
            issuedAtUnixNanos=unix, expiresAtUnixNanos=unix+10**9, emptyWitnessConvention=EMPTY_WITNESS_CONVENTION)
        self.assertEqual(local.approval(local.spec.canonical_json_bytes(value)), value)
        for changed in (dict(value, action="append", expectedHeadSha256=DIGEST),
                        dict(value, emptyWitnessConvention="caller-chosen"), dict(value, schema=local.APPROVAL_SCHEMA)):
            with self.assertRaises(ValueError): local.approval(local.spec.canonical_json_bytes(changed))
        legacy = dict(value); del legacy["emptyWitnessConvention"]
        legacy.update(schema=local.APPROVAL_SCHEMA, action="append", expectedHeadSha256=DIGEST)
        self.assertEqual(local.approval(local.spec.canonical_json_bytes(legacy)), legacy)

    def test_core_extraction_preserves_full_checkpoint_requirement(self):
        core, trust, private = fixture()
        local.spec.validate_generation_core(core)
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.validate_generation_statement(core)
        full = signed_generation(core, trust, private)
        local.spec.validate_generation_statement(full)
        self.assertEqual(local.spec.generation_core_digest(full),
            local.spec.domain_digest(local.spec.GENERATION_CORE_DIGEST_DOMAIN, local.spec.canonical_json_bytes(core)))
        for field in ("unexpected", "witnessCheckpoint"):
            with self.assertRaises(local.spec.ArtifactContractError):
                local.spec.validate_generation_core(dict(core, **{field: {}}))
        full["witnessCheckpoint"]["payload"]["rootDigest"] = DIGEST
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.validate_generation_statement(full)

    def test_native_core_still_validated_but_local_issuer_refuses_it(self):
        core, _, _ = fixture()
        core["trustMode"].update(mode="external-production", externalWitnessRequired=True, imaAppraisalRequired=True)
        local.spec.validate_generation_core(core)
        with self.assertRaises(ValueError):
            local._local_core(core)
        core["trustMode"]["hardwareBacked"] = True
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.validate_generation_core(core)

    def test_fixed_cli_rejects_aliases_paths_and_missing_pins(self):
        args = ["--approval-fd", "3", "--approval-sha256", DIGEST,
            "--trust-fd", "4", "--trust-sha256", DIGEST, "--core-fd", "5", "--core-sha256", DIGEST,
            "--directory-fd", "6", "--signing-key-fd", "7"]
        self.assertEqual(cli.arguments(args)["directory_fd"], 6)
        for wrong in (args + ["--reset"], args[:-1] + ["6"], [args[0], "03", *args[2:]], args[:-1]):
            with self.assertRaises(ValueError):
                cli.arguments(wrong)
        with self.assertRaises(ValueError):
            local.document(b'{"a":1,"a":2}')


@unittest.skipUnless(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
    and sys.flags.isolated and sys.flags.dont_write_bytecode, "real protected IO requires isolated root -I -B")
class WitnessStorageTests(unittest.TestCase):
    def test_real_v2_empty_anchors_initialize_then_legacy_append(self):
        from catchplate.authority_local_trust import empty_witness_anchors
        core, trust, _ = fixture()
        with tempfile.TemporaryDirectory(prefix="artifact-witness-v2-") as directory:
            info = os.stat(directory)
            witness = trust["witness"]
            anchors = empty_witness_anchors(dict(device=info.st_dev,inode=info.st_ino), identity=witness["identity"],
                key_id=witness["keyId"], key_file_sha256=witness["keyFileSha256"])
            witness.update(anchors)
            owner = open_owner(directory, core, trust, v2=True)
            first = local.document(owner.run())
            self.assertTrue(owner.committed and owner._closed)
            self.assertEqual(first["payload"]["previousCheckpointDigest"], anchors["currentCheckpointDigest"])
            self.assertEqual(first["payload"]["previousRootDigest"], anchors["currentRootDigest"])
            self.assertEqual(first["payload"]["previousTreeSize"], 0)
            core, trust, expected = successor(directory, trust)
            last = local.document(open_owner(directory, core, trust, action="append", expected=expected).run())
            self.assertEqual(last["payload"]["previousCheckpointDigest"], local.spec.witness_checkpoint_digest(first))

    def test_real_v2_mismatch_or_nonempty_refuses_before_lock_creation(self):
        from catchplate.authority_local_trust import empty_witness_anchors
        for nonempty in (False, True):
            with self.subTest(nonempty=nonempty), tempfile.TemporaryDirectory(prefix="artifact-witness-v2-") as directory:
                core, trust, _ = fixture()
                info = os.stat(directory); witness = trust["witness"]
                witness.update(empty_witness_anchors(dict(device=info.st_dev,inode=info.st_ino), identity=witness["identity"],
                    key_id=witness["keyId"], key_file_sha256=witness["keyFileSha256"]))
                if nonempty: (Path(directory) / "preserved").write_bytes(b"actual preexisting bytes")
                else: witness["currentRootDigest"] = DIGEST
                before = set(os.listdir(directory))
                owner = open_owner(directory, core, trust, v2=True)
                with self.assertRaises(local.LocalArtifactWitnessError): owner.run()
                owner.close()
                self.assertEqual(set(os.listdir(directory)), before)
                self.assertFalse((Path(directory) / local.LOCK_NAME).exists())

    def test_real_initialize_then_append_persists_existing_signed_chain(self):
        core, trust, _ = fixture()
        with tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
            owner = open_owner(directory, core, trust)
            checkpoint_raw = owner.run()
            self.assertTrue(owner.committed and owner._closed)
            self.assertEqual(owner._fds, [])
            generation = local.document((Path(directory) / local._name(0)).read_bytes())
            self.assertEqual(local.document(checkpoint_raw), generation["witnessCheckpoint"])
            core, trust, expected = successor(directory, trust)
            owner = open_owner(directory, core, trust, action="append", expected=expected)
            checkpoint = local.document(owner.run())
            self.assertEqual(checkpoint["payload"]["treeSize"], 2)
            self.assertEqual(checkpoint["payload"]["previousCheckpointDigest"], trust["witness"]["currentCheckpointDigest"])
            self.assertEqual(set(os.listdir(directory)), {local.LOCK_NAME, local.BASE_NAME, local.HEAD_NAME,
                                                          local._name(0), local._name(1)})
            self.assertEqual(local.document((Path(directory) / local.HEAD_NAME).read_bytes())["sequence"], 1)

    def test_real_stale_expected_head_cannot_append_or_retry(self):
        core, trust, _ = fixture()
        with tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
            open_owner(directory, core, trust).run()
            before = (Path(directory) / local.HEAD_NAME).read_bytes()
            core, trust, _ = successor(directory, trust)
            owner = open_owner(directory, core, trust, action="append", expected=DIGEST)
            with self.assertRaises(local.LocalArtifactWitnessError) as caught:
                owner.run()
            self.assertIs(caught.exception.owner, owner)
            owner.close()
            self.assertEqual((Path(directory) / local.HEAD_NAME).read_bytes(), before)
            self.assertFalse((Path(directory) / local._name(1)).exists())

    def test_real_unrecorded_tail_or_changed_signed_record_refuses(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
                core, trust, _ = fixture()
                open_owner(directory, core, trust).run()
                core, trust, expected = successor(directory, trust)
                if changed:
                    path = Path(directory) / local._name(0)
                    value = local.document(path.read_bytes())
                    value["witnessCheckpoint"]["signatureBase64Url"] = local.spec.strict_base64url_encode(b"x" * 64)
                    os.chmod(path, 0o600)
                    path.write_bytes(local.spec.canonical_json_bytes(value)); os.chmod(path, 0o400)
                else:
                    (Path(directory) / ".pending-head.json").write_bytes(b"preserved partial effect")
                owner = open_owner(directory, core, trust, action="append", expected=expected)
                with self.assertRaises(local.LocalArtifactWitnessError):
                    owner.run()
                owner.close()
                self.assertFalse((Path(directory) / local._name(1)).exists())

    def test_real_reinitialize_and_forked_predecessor_refuse(self):
        core, trust, _ = fixture()
        with tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
            open_owner(directory, core, trust).run()
            owner = open_owner(directory, core, trust)
            with self.assertRaises(local.LocalArtifactWitnessError):
                owner.run()
            owner.close()
            core, trust, expected = successor(directory, trust)
            core["predecessorDigest"] = DIGEST
            owner = open_owner(directory, core, trust, action="append", expected=expected)
            with self.assertRaises(local.LocalArtifactWitnessError):
                owner.run()
            owner.close()
            self.assertFalse((Path(directory) / local._name(1)).exists())

    def test_real_revoked_or_wrong_private_key_never_publishes_generation(self):
        for revoked in (False, True):
            with self.subTest(revoked=revoked), tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
                core, trust, _ = fixture()
                if revoked:
                    trust["revokedKeyIds"] = [trust["witness"]["keyId"]]
                owner = open_owner(directory, core, trust, seed=SEED if revoked else b"z" * 32)
                with self.assertRaises(local.LocalArtifactWitnessError):
                    owner.run()
                owner.close()
                self.assertEqual(os.listdir(directory), [local.LOCK_NAME])

    def test_real_exclusive_lock_and_partial_files_are_not_repaired(self):
        core, trust, _ = fixture()
        with tempfile.TemporaryDirectory(prefix="artifact-witness-") as directory:
            open_owner(directory, core, trust).run()
            core, trust, expected = successor(directory, trust)
            lock = os.open(Path(directory) / local.LOCK_NAME, os.O_RDWR)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                owner = open_owner(directory, core, trust, action="append", expected=expected)
                with self.assertRaises(local.LocalArtifactWitnessError):
                    owner.run()
                owner.close()
                self.assertFalse((Path(directory) / local._name(1)).exists())
            finally:
                os.close(lock)


if __name__ == "__main__":
    unittest.main()
