#!/usr/bin/env python3
"""Signed synthetic roster contracts and real bounded ELF reads; not deployment."""
import ast
import copy
import inspect
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import generate_artifact_bundle as generator
from scripts.authority import local_closure as cli
from scripts.authority import atomic_provisioner_contract as provisioning
from catchplate import authority_local_closure as local
from catchplate import authority_local_artifacts as artifacts

PIN = "sha256:" + "1" * 64
NOW = "2026-10-01T12:00:01Z"


def elf_bytes():
    header = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    return header + struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 4096)


def fixture():
    spec = local.spec
    private = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = spec.VerifiedAuthorityKey(key_id="synthetic-roster-key", purposes=frozenset({"closure-verifier", "stable-snapshot-verifier"}),
        public_key=public, key_file_path="", key_file_sha256=local.sha(public), authorization_digest=PIN,
        not_before="2026-10-01T00:00:00Z", not_after="2026-10-02T00:00:00Z")
    trust = dict(rootKeys={key.key_id: key}, currentKeys={}, revokedKeyIds=frozenset(), acceptedEvidenceDigests=frozenset())
    stage = dict(path="bootstrap.py", sha256=local.sha(b"pass\n"), size=5, runtimePath="/runtime/bootstrap.py",
        interfaceSchema=spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA,
        interpreter=dict(path="python", sha256=local.sha(elf_bytes()), size=120, runtimePath="/runtime/python"))
    native = dict(executables=[dict(path="python", runtimePath="/runtime/python", elfClass="ELF64", machine=62,
        ptInterp=None, needed=[], sha256=stage["interpreter"]["sha256"])], objects=[])
    snapshot_payload = dict(schema="catchplate.authorityStableSnapshotReceiptPayload/v1",
        rootIdentity=dict(runtimePath="/synthetic/frozen", device=1, inode=2, generation=3, mountId=4, mode=0o500, uid=0, gid=0),
        snapshotKind="content-addressed-cas", readOnly=True, treeAlgorithm="canonical-path-tree-sha256-v1",
        treeDigest=PIN, treeEntryCount=2, totalBytes=125, enumeratedTreeDigest=PIN,
        createdAt="2026-10-01T12:00:00Z", expiresAt="2026-10-01T12:10:00Z")
    snapshot_payload["receiptId"] = spec.domain_digest("catchplate.authorityStableSnapshotReceiptId/v1", spec.canonical_json_bytes(snapshot_payload))
    snapshot = signed(snapshot_payload, spec.SNAPSHOT_RECEIPT_SCHEMA,
        "catchplate.authorityStableSnapshotReceiptSignature/v1", private, key.key_id)
    payload = dict(schema="catchplate.authorityTrustedHostLocalMeasuredRosterPayload/v1",
        snapshotReceiptDigest=spec.snapshot_receipt_digest(snapshot), treeDigest=PIN, treeEntryCount=2, totalBytes=125,
        pythonImportClosure=[], nativeClosure=native, stageZero=stage, assurance=dict(spec.LOCAL_CLOSURE_CLAIMS),
        createdAt="2026-10-01T12:00:00Z", expiresAt="2026-10-01T12:05:00Z")
    payload["receiptId"] = spec.domain_digest("catchplate.authorityTrustedHostLocalMeasuredRosterId/v1", spec.canonical_json_bytes(payload))
    receipt = signed(payload, spec.LOCAL_CLOSURE_RECEIPT_SCHEMA, spec.LOCAL_CLOSURE_SIGNATURE_DOMAIN, private, key.key_id)
    return receipt, snapshot, trust, private


def signed(payload, schema, domain, private, key_id):
    signature = private.sign(local.spec._signature_message(domain, payload))
    return dict(schema=schema, payload=payload, signerKeyId=key_id, algorithm="Ed25519",
        signatureBase64Url=local.spec.strict_base64url_encode(signature))


class LocalClosureTests(unittest.TestCase):
    def test_genuine_synthetic_signature_joins_existing_generator(self):
        receipt, snapshot, trust, _ = fixture()
        local.spec.validate_local_closure_receipt(receipt)
        result = generator._verify_snapshot_and_closure(snapshot, receipt, trust=trust,
            validation_time=NOW, trust_mode="trusted-host-local")
        self.assertEqual(result, (local.spec.snapshot_receipt_digest(snapshot), local.spec.closure_receipt_digest(receipt)))
        self.assertEqual(local.spec.closure_signature_domain(receipt), local.spec.LOCAL_CLOSURE_SIGNATURE_DOMAIN)
        self.assertNotIn("rootfs", receipt["payload"])
        self.assertEqual(receipt["payload"]["assurance"]["futureDynamicLoading"], "not-proven")

    def test_cross_profile_and_complete_schema_substitution_refuse(self):
        receipt, snapshot, trust, _ = fixture()
        for mode in (None, "external-production", "tee-hardware"):
            with self.subTest(mode=mode), self.assertRaises(local.spec.ArtifactContractError):
                generator._verify_snapshot_and_closure(snapshot, receipt, trust=trust, validation_time=NOW, trust_mode=mode)
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.validate_closure_receipt(receipt)
        wrong = copy.deepcopy(receipt); wrong["schema"] = local.spec.CLOSURE_RECEIPT_SCHEMA
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.closure_receipt_digest(wrong)
        wrong = copy.deepcopy(receipt); wrong["payload"]["assurance"]["rootfsIsolation"] = "proven"
        with self.assertRaises(local.spec.ArtifactContractError):
            local.spec.validate_local_closure_receipt(wrong)

    def test_native_complete_receipt_domain_and_coverage_remain_strict(self):
        local_receipt, snapshot, trust, private = fixture()
        payload = copy.deepcopy(local_receipt["payload"])
        del payload["receiptId"]; del payload["assurance"]
        payload["schema"] = "catchplate.authorityCompleteClosureReceiptPayload/v1"
        payload["coverage"] = {name: True for name in ("pythonStaticImports", "pythonDynamicImports", "ptInterp", "dtNeeded",
            "rpath", "runpath", "audit", "depaudit", "filter", "auxiliary", "dlopen", "nss", "plugins", "ifunc", "hwcap")}
        payload["coverage"]["coverageEvidenceDigest"] = PIN
        payload["rootfs"] = dict(imageDigest=PIN, verityRootDigest=PIN, mountPolicyDigest=PIN,
            pivotRootRequired=True, oldRootDetached=True, enforcementEvidenceDigest=PIN)
        payload["receiptId"] = local.spec.domain_digest("catchplate.authorityCompleteClosureReceiptId/v1", local.spec.canonical_json_bytes(payload))
        receipt = signed(payload, local.spec.CLOSURE_RECEIPT_SCHEMA, generator.CLOSURE_SIGNATURE_DOMAIN,
                         private, local_receipt["signerKeyId"])
        local.spec.validate_closure_receipt(receipt)
        generator._verify_snapshot_and_closure(snapshot, receipt, trust=trust, validation_time=NOW)
        self.assertEqual(local.spec.closure_receipt_digest(receipt), local.spec.domain_digest(
            "catchplate.authorityCompleteClosureReceiptDigest/v1", local.spec.canonical_json_bytes(receipt)))
        for field in ("dlopen", "pythonDynamicImports"):
            changed = copy.deepcopy(receipt); changed["payload"]["coverage"][field] = False
            with self.assertRaises(local.spec.ArtifactContractError):
                local.spec.validate_closure_receipt(changed)

    def test_wrong_signature_domain_revocation_and_consumed_snapshot_refuse(self):
        receipt, snapshot, trust, private = fixture()
        wrong = signed(receipt["payload"], receipt["schema"], generator.CLOSURE_SIGNATURE_DOMAIN, private, receipt["signerKeyId"])
        with self.assertRaises(local.spec.ArtifactContractError):
            generator._verify_snapshot_and_closure(snapshot, wrong, trust=trust, validation_time=NOW, trust_mode="trusted-host-local")
        for changes in (dict(revokedKeyIds=frozenset({receipt["signerKeyId"]})),
                        dict(acceptedEvidenceDigests=frozenset({local.spec.snapshot_receipt_digest(snapshot)}))):
            with self.assertRaises(generator.GeneratorError):
                generator._verify_snapshot_and_closure(snapshot, receipt, trust=dict(trust, **changes),
                    validation_time=NOW, trust_mode="trusted-host-local")

    def test_actual_bounded_elf_header_read_and_wrong_architecture_refusal(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(elf_bytes()); stream.flush()
            calls = []
            result = local.elf_metadata(stream.fileno(), check=lambda: calls.append(True))
            self.assertEqual(result, dict(elfClass="ELF64", machine=62, ptInterp=None, needed=[], soname=None))
            self.assertGreater(len(calls), 2)
            stream.seek(18); stream.write(struct.pack("<H", 183)); stream.flush()
            with self.assertRaises(ValueError):
                local.elf_metadata(stream.fileno(), check=lambda: None)

    def test_json_schema_discriminates_local_roster_and_original_complete(self):
        import jsonschema
        receipt, _, _, _ = fixture()
        jsonschema.Draft202012Validator(local.spec.LOCAL_CLOSURE_RECEIPT_JSON_SCHEMA).validate(receipt)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(local.spec.CLOSURE_RECEIPT_JSON_SCHEMA).validate(receipt)
        # Only the new cross-profile conditional is tested here, not a fake package.
        condition = local.spec.ARTIFACT_BUNDLE_JSON_SCHEMA["allOf"][1]
        fragment = dict(closureReceipt=receipt, stageZero=receipt["payload"]["stageZero"], trustMode=dict(mode="trusted-host-local"))
        jsonschema.Draft202012Validator(condition).validate(fragment)
        fragment["trustMode"]["mode"] = "external-production"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(condition).validate(fragment)
        provenance_condition = local.spec.ARTIFACT_BUNDLE_JSON_SCHEMA["allOf"][2]
        for predicate in local.spec.LOCAL_PROVENANCE_PREDICATES:
            source = dict(provenance=dict(predicateType=predicate), stageZero=receipt["payload"]["stageZero"],
                          trustMode=dict(mode="trusted-host-local"))
            jsonschema.Draft202012Validator(provenance_condition).validate(source)
            source["trustMode"]["mode"] = "tee-hardware"
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(provenance_condition).validate(source)

    def test_actual_writable_tree_cannot_become_frozen_roster_evidence(self):
        with tempfile.TemporaryDirectory(prefix="local-roster-refusal-") as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises((ValueError, OSError)):
                    local.measure.root_identity(fd, directory)
            finally:
                os.close(fd)

    def test_fixed_cli_and_source_measure_before_key_access_and_local_complete_false(self):
        args = ["--approval-fd", "3", "--approval-sha256", PIN, "--trust-fd", "4", "--trust-sha256", PIN,
            "--snapshot-fd", "5", "--snapshot-sha256", PIN, "--source-root-fd", "6", "--signing-key-fd", "7"]
        self.assertEqual(cli.arguments(args)["snapshot_fd"], 5)
        for wrong in (args+['--complete'], args[:-1]+['6'], [args[0], '03', *args[2:]]):
            with self.assertRaises(ValueError):
                cli.arguments(wrong)
        tree = ast.parse(inspect.getsource(local))
        issuer = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == "LocalClosureIssuer")
        issue = next(row for row in issuer.body if isinstance(row, ast.FunctionDef) and row.name == "issue")
        calls = list(row for row in ast.walk(issue) if isinstance(row, ast.Call))
        measurement = next(row.lineno for row in calls if isinstance(row.func, ast.Attribute) and row.func.attr == "measure_tree")
        keyread = next(row.lineno for row in calls if isinstance(row.func, ast.Attribute) and row.func.attr == "signing_key")
        self.assertLess(measurement, keyread)
        self.assertIn('complete=not local_roster', inspect.getsource(artifacts._receipt))
        self.assertIn('closure["complete"] is not False', inspect.getsource(provisioning.validate_verification_receipt))


if __name__ == "__main__":
    unittest.main()
