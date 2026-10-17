#!/usr/bin/env python3
"""Synthetic public/signature controls and real empty-directory observations.

No fixture claims an installed key, independently approved trust, or accepted
artifact generation. The actual protected-descriptor CLI is not simulated.
"""
from __future__ import annotations

import ast
import copy
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catchplate import authority_local_trust as local
from scripts.authority import local_trust as cli

NOW = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()) * 10**9
DIGEST = "sha256:" + "1" * 64


def fixture():
    private = {purpose: Ed25519PrivateKey.from_private_bytes(bytes([index+1])*32)
        for index, purpose in enumerate(local.PURPOSES)}
    public = {purpose: local.spec.strict_base64url_encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)) for purpose, key in private.items()}
    entries = local.key_entries(public, not_before="2026-09-30T00:00:00Z", not_after="2026-10-02T00:00:00Z")
    root = next(entry for entry in entries if entry["purposes"] == [local.ROOT_PURPOSE])
    witness = next(entry for entry in entries if entry["purposes"] == ["witness-checkpoint"])
    initial = dict(convention=local.EMPTY_WITNESS_CONVENTION, identity="synthetic-local-artifact-log",
        directory=dict(device=1, inode=2))
    trust = dict(schema=local.spec.TRUST_STATE_SCHEMA, currentGenerationSequence=-1,
        currentGenerationDigest=None, currentPackageDigest=None, minimumRollbackSequence=0,
        acceptedPackageDigests=[], acceptedGenerationDigests=[], acceptedEvidenceDigests=[], revokedKeyIds=[],
        rootKeys=[local.external_key(root)], currentKeys=[local.external_key(entry) for entry in entries if entry is not root],
        witness=dict(identity=initial["identity"], keyId=witness["keyId"], publicKeyBase64Url=witness["publicKeyBase64Url"],
            keyFileSha256=witness["keyFile"]["sha256"], authorizationDigest=witness["authorizationDigest"],
            currentSequence=-1, currentTreeSize=0, **local.empty_witness_anchors(initial["directory"],
                identity=initial["identity"], key_id=witness["keyId"], key_file_sha256=witness["keyFile"]["sha256"])))
    selected = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE,
        trustSha256=local.sha(local.spec.canonical_json_bytes(trust)), publicKeysSha256=local.sha(local.spec.canonical_json_bytes(public)),
        signerKeyId=root["keyId"], generation=dict(sequence=0, predecessorDigest=None, minimumRollbackSequence=0,
            validFrom=root["notBefore"], validUntil=root["notAfter"], stageZeroContract=local.spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
            trustMode=dict(local.LOCAL_TRUST_MODE)),
        initialRevocations=dict(state="explicit-empty-initial-history", revocationHighWater=0, revocations=[]),
        initialWitness=initial, bootIdDigest=DIGEST, issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=NOW-1_000_000_000, expiresAtUnixNanos=NOW+1_000_000_000)
    return dict(selected=selected, trust=trust, public=public, private=private)


def prepare(f, *, repin=False, **clocks):
    trust_raw, public_raw = (local.spec.canonical_json_bytes(f[name]) for name in ("trust", "public"))
    selected = copy.deepcopy(f["selected"])
    if repin:
        selected.update(trustSha256=local.sha(trust_raw), publicKeysSha256=local.sha(public_raw))
    return local.prepare(local.spec.canonical_json_bytes(selected), trust_raw, public_raw,
        **dict(dict(boot=DIGEST, now_boottime_ns=150, now_unix_ns=NOW), **clocks))


class InitialTrustTests(unittest.TestCase):
    def test_existing_signed_documents_and_canonical_entry_bindings(self):
        f = fixture(); context = prepare(f)
        raw = local.sign_documents(context, f["private"][local.ROOT_PURPOSE], validation_time="2026-10-01T00:00:00Z")
        material = local.document(raw, local.MAX_ORIGINAL)
        self.assertEqual(set(material), {"keyAuthorizations", "keyRevocations"})
        self.assertEqual(len(material["keyAuthorizations"]["payload"]["keys"]), 12)
        self.assertEqual(material["keyRevocations"]["payload"], dict(schema="catchplate.authorityKeyRevocationPayload/v1",
            generationSequence=0, predecessorGenerationDigest=None, revocationHighWater=0, revocations=[]))
        for name, schema, domain in (("keyAuthorizations", local.spec.KEY_AUTHORIZATION_SCHEMA, local.spec.KEY_AUTHORIZATION_SIGNATURE_DOMAIN),
                ("keyRevocations", local.spec.KEY_REVOCATION_SCHEMA, local.spec.KEY_REVOCATION_SIGNATURE_DOMAIN)):
            self.assertEqual(local.spec._validate_signed_trust_document(material[name], expected_schema=schema,
                signature_domain=domain, trust_state=context["trust"], validation_time="2026-10-01T00:00:00Z"), material[name]["payload"])

    def test_no_invented_current_state_or_replay_reset(self):
        for name, value in (("minimumRollbackSequence", 1), ("acceptedEvidenceDigests", [DIGEST]),
                            ("revokedKeyIds", [local.key_id("generation")]), ("currentGenerationSequence", 0)):
            f = fixture(); f["trust"][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError): prepare(f, repin=True)
        for name, value in (("sequence", 1), ("predecessorDigest", DIGEST), ("minimumRollbackSequence", True)):
            f = fixture(); f["selected"]["generation"][name] = value
            with self.subTest(field=name), self.assertRaises(ValueError): prepare(f)

    def test_explicit_empty_revocation_and_original_caps(self):
        for changed in (dict(state="implicit", revocationHighWater=0, revocations=[]),
                        dict(state="explicit-empty-initial-history", revocationHighWater=True, revocations=[]),
                        dict(state="explicit-empty-initial-history", revocationHighWater=1, revocations=[])):
            f = fixture(); f["selected"]["initialRevocations"] = changed
            with self.assertRaises(ValueError): prepare(f)
        for clocks in (dict(now_boottime_ns=200), dict(now_unix_ns=NOW+1_000_000_000), dict(boot="sha256:"+"2"*64)):
            with self.assertRaises(ValueError): prepare(fixture(), **clocks)
        f = fixture(); f["selected"]["deadlineBoottimeNs"] = 101+local.MAX_OPERATION_NS
        with self.assertRaises(ValueError): prepare(f)

    def test_distinct_fixed_purposes_and_exact_public_original(self):
        f = fixture(); f["public"]["artifact-bundle"] = f["public"][local.ROOT_PURPOSE]
        with self.assertRaises(ValueError): prepare(f, repin=True)
        f = fixture(); f["public"].pop("provenance")
        with self.assertRaises(ValueError): prepare(f, repin=True)
        f = fixture(); f["trust"]["currentKeys"][0]["purposes"] = ["trust-document"]
        with self.assertRaises(ValueError): prepare(f, repin=True)
        f = fixture(); f["trust"]["rootKeys"][0]["authorizationDigest"] = DIGEST
        with self.assertRaises(ValueError): prepare(f, repin=True)

    def test_nonlocal_claims_and_wrong_root_never_issue(self):
        for field, value in (("mode", "external-production"), ("hardwareBacked", True), ("hardwareBacked", 0)):
            f = fixture(); f["selected"]["generation"]["trustMode"][field] = value
            with self.assertRaises(ValueError): prepare(f)
        f = fixture()
        with self.assertRaises(ValueError):
            local.sign_documents(prepare(f), f["private"]["artifact-bundle"], validation_time="2026-10-01T00:00:00Z")

    def test_directory_bound_empty_anchors_are_not_prior_checkpoints(self):
        f = fixture(); witness = f["trust"]["witness"]
        args = dict(identity=witness["identity"], key_id=witness["keyId"], key_file_sha256=witness["keyFileSha256"])
        a = local.empty_witness_anchors(dict(device=1, inode=2), **args)
        self.assertNotEqual(a["currentCheckpointDigest"], a["currentRootDigest"])
        self.assertNotEqual(a, local.empty_witness_anchors(dict(device=1, inode=3), **args))
        f["selected"]["initialWitness"]["directory"]["inode"] += 1
        with self.assertRaises(ValueError): prepare(f)

    def test_actual_empty_directory_then_nonempty_refusal(self):
        if os.getuid() != 0: self.skipTest("actual protected directory control requires root ownership")
        with tempfile.TemporaryDirectory(prefix="local-trust-empty-") as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
            try:
                info = os.fstat(fd)
                self.assertEqual(local.empty_directory(fd), dict(device=info.st_dev, inode=info.st_ino))
                child = os.open("unexpected", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400, dir_fd=fd)
                os.close(child)
                with self.assertRaises(ValueError): local.empty_directory(fd)
            finally: os.close(fd)

    def test_fixed_cli_and_private_read_after_guards(self):
        args = ["--approval-fd","3","--approval-sha256",DIGEST,"--trust-fd","4","--trust-sha256",DIGEST,
            "--public-keys-fd","5","--public-keys-sha256",DIGEST,"--witness-directory-fd","6","--signing-key-fd","7"]
        self.assertEqual(cli.arguments(args)["witness_directory_fd"], 6)
        for wrong in (args+["--reset"], [args[0],"03",*args[2:]], args[:-1]+["3"]):
            with self.assertRaises(ValueError): cli.arguments(wrong)
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == "LocalTrustIssuer")
        issue = next(row for row in owner.body if isinstance(row, ast.FunctionDef) and row.name == "issue")
        calls = [(row.lineno, row.func.attr) for row in ast.walk(issue) if isinstance(row, ast.Call) and isinstance(row.func,ast.Attribute)]
        self.assertLess(min(line for line,name in calls if name == "check"), min(line for line,name in calls if name == "signing_key"))
        self.assertNotIn("os.open(", Path(local.__file__).read_text())


if __name__ == "__main__": unittest.main()
