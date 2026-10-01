#!/usr/bin/env python3
"""Synthetic receipt/contract controls, not an observed immutable snapshot."""
from __future__ import annotations

import copy
import ast
from datetime import datetime, timezone
import os
import inspect
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_snapshot as cli
from serverware import authority_local_snapshot as local

NOW = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
DIGEST = "sha256:" + "1" * 64


def fixture():
    return dict(schema=local.APPROVAL_SCHEMA, trustSha256=DIGEST, signerKeyId="local-snapshot-test",
        sourceRoot=dict(runtimePath="/test/cas/sha256-" + DIGEST[7:], device=1, inode=2),
        treeDigest=DIGEST, files=[dict(path="file", kind="authority-source", mode=0o400, uid=0, gid=0)],
        bootIdDigest=DIGEST, issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
        issuedAtUnixNanos=NOW, expiresAtUnixNanos=NOW+1_000_000_000,
        receiptValidUntil="2026-10-01T00:01:00Z")


def synthetic_owner():
    """Exercise signing logic only; never claim these fixture observations ran."""
    owner = local.LocalSnapshotIssuer.__new__(local.LocalSnapshotIssuer)
    owner.used = False
    owner.selected = fixture()
    owner.previous_unix_ns = NOW
    owner.source_root_fd, owner.signing_key_fd = 40, 41
    owner.check = lambda: None
    owner.check_originals = lambda: None
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    authority = local.spec.VerifiedAuthorityKey(key_id="local-snapshot-test",
        purposes=frozenset({"stable-snapshot-verifier"}), public_key=public,
        key_file_path="", key_file_sha256=local._sha(public), authorization_digest=DIGEST,
        not_before="2026-09-30T00:00:00Z", not_after="2026-10-02T00:00:00Z")
    owner.trust = dict(rootKeys={}, currentKeys={authority.key_id: authority},
                       revokedKeyIds=frozenset(), acceptedEvidenceDigests=frozenset())
    measured = dict(rootIdentity=dict(owner.selected["sourceRoot"], generation=3,
        mountId=4, mode=0o500, uid=0, gid=0), files=[dict(owner.selected["files"][0],
        size=1, sha256=DIGEST)], treeDigest=DIGEST, enumeratedTreeDigest=DIGEST, totalBytes=1)
    return owner, private, measured


class LocalSnapshotTests(unittest.TestCase):
    def test_measured_root_remains_in_actual_output_check_path(self):
        # Source-order regression only, not a claim of successful frozen IO.
        tree = ast.parse(inspect.getsource(local))
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalSnapshotIssuer")
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        calls = [node for node in ast.walk(methods["check"]) if isinstance(node, ast.Call)]
        self.assertTrue(any(isinstance(node.func, ast.Attribute) and node.func.attr == "root_identity" for node in calls))
        retained = [node.lineno for node in ast.walk(methods["issue"]) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Attribute) and target.attr == "measured_root" for target in node.targets)]
        key_reads = [node.lineno for node in ast.walk(methods["issue"]) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "signing_key"]
        self.assertEqual(len(retained), 1)
        self.assertLess(retained[0], min(key_reads))

    def test_closed_approval_binds_content_address_and_original_limits(self):
        value = fixture()
        self.assertEqual(local.approval(local.spec.canonical_json_bytes(value)), value)
        changes = []
        row = copy.deepcopy(value); row["sourceRoot"]["runtimePath"] = "/test/mutable"; changes.append(row)
        row = copy.deepcopy(value); row["freezeFiles"] = True; changes.append(row)
        row = copy.deepcopy(value); row["deadlineBoottimeNs"] = 100 + local.MAX_OPERATION_NS + 1; changes.append(row)
        row = copy.deepcopy(value); row["receiptValidUntil"] = "2026-10-03T00:00:00Z"; changes.append(row)
        row = copy.deepcopy(value); row["files"][0]["uid"] = True; changes.append(row)
        row = copy.deepcopy(value); row["files"][0]["mode"] = 0o666; changes.append(row)
        for row in changes:
            with self.subTest(row=row), self.assertRaises(ValueError):
                local.approval(local.spec.canonical_json_bytes(row))

    def test_canonical_input_and_fixed_fd_only_cli(self):
        with self.assertRaises(ValueError):
            local._document(b'{"a":1,"a":2}')
        args = ["--approval-fd", "3", "--approval-sha256", DIGEST,
            "--trust-fd", "4", "--trust-sha256", DIGEST, "--source-root-fd", "5", "--signing-key-fd", "6"]
        self.assertEqual(cli.arguments(args)["source_root_fd"], 5)
        for wrong in (args + ["--freeze"], [args[0], "03", *args[2:]], []):
            with self.assertRaises(ValueError):
                cli.arguments(wrong)

    def test_synthetic_measured_receipt_uses_existing_signature_contract_once(self):
        owner, private, measured = synthetic_owner()
        with patch.object(local.measure, "measure_tree", return_value=measured) as measurement, \
             patch.object(local.io, "signing_key", return_value=private):
            raw = owner.issue()
            receipt = local._document(raw)
            local.spec.validate_snapshot_receipt(receipt)
            self.assertEqual(receipt["payload"]["rootIdentity"], measured["rootIdentity"])
            message = local.spec.domain_digest(local.SIGNATURE_DOMAIN,
                local.spec.canonical_json_bytes(receipt["payload"])).encode("ascii")
            private.public_key().verify(local.spec.strict_base64url_decode(
                receipt["signatureBase64Url"], name="test signature", decoded_size=64), message)
            measurement.assert_called_once()
            with self.assertRaises(ValueError):
                owner.issue()

    def test_missing_kernel_proof_refuses_before_private_key_read(self):
        owner, _, _ = synthetic_owner()
        with patch.object(local.measure, "measure_tree", side_effect=OSError(95, "unsupported")), \
             patch.object(local.io, "signing_key") as key:
            with self.assertRaises(OSError):
                owner.issue()
            key.assert_not_called()
            self.assertTrue(owner.used)

    def test_changed_tree_or_root_refuses_before_private_key_read(self):
        for field in ("treeDigest", "rootIdentity"):
            owner, _, measured = synthetic_owner()
            if field == "treeDigest":
                measured[field] = "sha256:" + "2" * 64
            else:
                measured[field]["inode"] += 1
            with patch.object(local.measure, "measure_tree", return_value=measured), \
                 patch.object(local.io, "signing_key") as key:
                with self.assertRaises(ValueError):
                    owner.issue()
                key.assert_not_called()

    def test_revoked_or_mismatching_key_never_returns_receipt(self):
        owner, private, measured = synthetic_owner()
        owner.trust["revokedKeyIds"] = frozenset({"local-snapshot-test"})
        with patch.object(local.measure, "measure_tree", return_value=measured), \
             patch.object(local.io, "signing_key", return_value=private) as key:
            with self.assertRaises(ValueError):
                owner.issue()
            key.assert_not_called()
        owner, _, measured = synthetic_owner()
        with patch.object(local.measure, "measure_tree", return_value=measured), \
             patch.object(local.io, "signing_key", return_value=Ed25519PrivateKey.generate()):
            with self.assertRaises(ValueError):
                owner.issue()

    def test_actual_writable_temporary_tree_is_not_snapshot_proof(self):
        with tempfile.TemporaryDirectory(prefix="snapshot-refusal-") as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                with self.assertRaises((ValueError, OSError)):
                    local.measure.root_identity(fd, directory)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
