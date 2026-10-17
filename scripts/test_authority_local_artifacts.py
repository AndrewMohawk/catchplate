#!/usr/bin/env python3
"""Real bounded primitives and refusals, not a complete package/installation."""
import ast
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import authority_local_artifacts as local
from catchplate import authority_local_artifact_measure as measure
from scripts.authority import local_artifacts as cli
from scripts.authority import generate_artifact_bundle as generator
from catchplate import authority_launcher as launcher


class OCIOriginalControls(unittest.TestCase):
    @contextmanager
    def original(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oci.json"
            path.write_bytes(raw)
            path.chmod(0o400)
            row = dict(path=path.name, size=len(raw),
                sha256="sha256:" + hashlib.sha256(raw).hexdigest())
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd, row
            finally:
                os.close(fd)

    def test_preserves_original_oci_encoding_and_digest(self):
        originals = (
            b'{"schemaVersion":2, "annotations":{"z":"\\u003c\\u0026\\u003e", "a":"x"}}\n',
            b'{"a":1,"z":2}',
        )
        for raw in originals:
            with self.subTest(raw=raw), self.original(raw) as (fd, row):
                path, observed, document = generator._oci_document(
                    fd, {row["path"]: row}, row["path"], name="OCI manifest")
                self.assertEqual(path, row["path"])
                self.assertIs(observed, row)
                self.assertEqual(document, raw)
                self.assertEqual("sha256:" + hashlib.sha256(document).hexdigest(), row["sha256"])

    def test_rejects_ambiguous_or_invalid_oci_json(self):
        originals = (
            b'{"a":1,"a":2}', b'{"config":{"a":1,"a":2}}',
            b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
            b'[]', b'null', b'{', b'{"a":"\xff"}',
        )
        for raw in originals:
            with self.subTest(raw=raw), self.original(raw) as (fd, row):
                with self.assertRaises(generator.GeneratorError):
                    generator._oci_document(fd, {row["path"]: row}, row["path"], name="OCI manifest")

    def test_original_digest_and_size_remain_enforced(self):
        with self.original(b'{"a":1}') as (fd, row):
            for changes in ({"sha256": "sha256:" + "0" * 64}, {"size": row["size"] + 1}):
                changed = dict(row, **changes)
                with self.subTest(changes=changes), self.assertRaises(generator.GeneratorError):
                    generator._oci_document(fd, {row["path"]: changed}, row["path"], name="OCI manifest")

    def test_oci_document_requires_measured_tree_membership(self):
        with self.original(b'{}') as (fd, row):
            with self.assertRaises(generator.GeneratorError):
                generator._oci_document(fd, {}, row["path"], name="OCI manifest")

    def test_oci_document_keeps_existing_size_bound(self):
        with self.original(b'{}') as (fd, row):
            changed = dict(row, size=generator.MAX_TARGET_DOCUMENT_BYTES + 1)
            with self.assertRaises(generator.GeneratorError):
                generator._oci_document(fd, {row["path"]: changed}, row["path"], name="OCI manifest")

    def test_catchplate_canonical_document_contract_is_unchanged(self):
        with self.original(b'{ "a": 1 }\n') as (fd, row):
            with self.assertRaises(generator.GeneratorError):
                generator._canonical_json_document(fd, row["path"], row, name="Catchplate document")


def selection():
    digest = "sha256:" + "1" * 64
    return dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE,
        unsignedPackageSha256=digest, trustStateSha256=digest,
        signingKeys={name: "test-key" for name in local.KEY_PURPOSES},
        verifierIdentity="synthetic-verifier", verifierSourceSha256=digest,
        verificationValidUntil="2030-01-01T00:00:02Z", outputDirectory=dict(device=1, inode=2),
        bootIdDigest=digest, issuedAtBoottimeNs=1, deadlineBoottimeNs=100,
        issuedAtUnixNanos=1893456000000000000, expiresAtUnixNanos=1893456003000000000)


class LocalArtifactControls(unittest.TestCase):
    @staticmethod
    def launcher_roles():
        return [dict(role=name, runtimeUid=launcher.ROLE_IDENTITIES[name][0],
            runtimeGid=launcher.ROLE_IDENTITIES[name][1], processMode=launcher.PROCESS_MODES[name],
            listenerName=launcher.ROLE_LISTENER_NAMES[name],
            credentialNames=sorted(launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES[name]))
            for name in sorted(launcher.PROCESS_MODES)]

    def test_generator_accepts_actual_launcher_credential_rosters(self):
        roles = self.launcher_roles()
        planner = next(row for row in roles if row["role"] == "planner")
        self.assertIn("CATCHPLATE_RBAC_WITNESS_CLIENT_KEY_FD", planner["credentialNames"])
        generator._validate_required_role_manifests(roles)

    def test_generator_refuses_missing_witness_or_extra_credentials(self):
        for mutation in ("missing-witness", "extra"):
            roles = self.launcher_roles()
            planner = next(row for row in roles if row["role"] == "planner")
            if mutation == "missing-witness":
                planner["credentialNames"].remove("CATCHPLATE_RBAC_WITNESS_CLIENT_KEY_FD")
            else:
                planner["credentialNames"].append("UNAPPROVED_KEY_FD")
                planner["credentialNames"].sort()
            with self.subTest(mutation=mutation), self.assertRaises(generator.GeneratorError):
                generator._validate_required_role_manifests(roles)

    def test_generator_preserves_exact_launcher_role_identity(self):
        for name in ("planner", "planner-writer"):
            roles = self.launcher_roles()
            next(row for row in roles if row["role"] == name)["runtimeUid"] += 1
            with self.subTest(role=name), self.assertRaises(generator.GeneratorError):
                generator._validate_required_role_manifests(roles)

    def test_canonical_public_originals_only(self):
        self.assertEqual(local.document(b'{"public":1}', 32), {"public": 1})
        for raw in (b'{ "public":1}', b'{"public":1,"public":2}', b'{"public":1.0}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                local.document(raw, 64)

    def test_exact_approval_and_original_two_clock_limits(self):
        value = selection()
        params = dict(unsigned_sha256=value["unsignedPackageSha256"], trust_sha256=value["trustStateSha256"],
                      boot=value["bootIdDigest"], now_boot=50, now_unix=value["issuedAtUnixNanos"] + 1)
        self.assertEqual(local.approval(value, **params), value)
        for changed in ({"purpose": "approve-anything"}, {"deadlineBoottimeNs": 50},
                        {"issuedAtUnixNanos": params["now_unix"] + 1}, {"expiresAtUnixNanos": params["now_unix"]},
                        {"verificationValidUntil": "2030-01-01T00:00:04Z"}, {"extra": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                local.approval(dict(value, **changed), **params)

    def test_actual_file_hash_and_chunk_callback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public"
            raw = b"x" * (1024 * 1024 + 1)
            path.write_bytes(raw)
            path.chmod(0o400)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                calls = []
                info = path.stat()
                row = measure.measure_file(fd, dict(path="public", kind="configuration", mode=0o400,
                    uid=info.st_uid, gid=info.st_gid), check=lambda: calls.append(True))
                self.assertEqual(row["sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
                self.assertEqual(row["size"], len(raw))
                self.assertGreaterEqual(len(calls), 4)
            finally:
                os.close(fd)

    def test_symlink_and_fifo_refuse_before_any_hash_read(self):
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory) / "pipe", 0o400)
            os.symlink("pipe", Path(directory) / "link")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for name in ("pipe", "link"):
                    with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                        measure.measure_file(fd, dict(path=name, kind="configuration", mode=0o400,
                            uid=os.getuid(), gid=os.getgid()), check=lambda: None)
            finally:
                os.close(fd)

    def test_callback_failure_does_not_return_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                def fail():
                    raise TimeoutError("test original deadline")
                with self.assertRaises(TimeoutError):
                    measure.measure_file(fd, dict(path="absent", kind="configuration", mode=0o400,
                        uid=os.getuid(), gid=os.getgid()), check=fail)
            finally:
                os.close(fd)

    def test_actual_publication_complete_and_no_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                local.publish(fd, "package.json", b'{"public":1}', check=lambda: None)
                self.assertEqual((Path(directory) / "package.json").read_bytes(), b'{"public":1}')
                self.assertEqual((Path(directory) / "package.json").stat().st_mode & 0o777, 0o400)
                with self.assertRaises(FileExistsError):
                    local.publish(fd, "package.json", b'{"public":2}', check=lambda: None)
                self.assertEqual((Path(directory) / "package.json").read_bytes(), b'{"public":1}')
                self.assertTrue((Path(directory) / ".package.json.pending").exists())
            finally:
                os.close(fd)

    def test_partial_publication_never_exposes_final_name(self):
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            calls = []
            try:
                def check():
                    calls.append(True)
                    if len(calls) == 2:
                        raise TimeoutError("test original deadline")
                with self.assertRaises(TimeoutError):
                    local.publish(fd, "verification.json", b'{"public":1}', check=check)
                self.assertFalse((Path(directory) / "verification.json").exists())
                self.assertTrue((Path(directory) / ".verification.json.pending").exists())
            finally:
                os.close(fd)

    def test_cli_has_only_fixed_fd_and_public_pin_arguments(self):
        digest = "sha256:" + "1" * 64
        args = []
        number = 3
        for name in cli.OPTIONS:
            args.extend(["--" + name, str(number) if name.endswith("-fd") else digest])
            number += name.endswith("-fd")
        self.assertEqual(cli.arguments(args)["unsigned_fd"], 3)
        for changed in (args + ["--command", "true"], args[2:], ["--trust-fd", *args[1:]]):
            with self.assertRaises(ValueError):
                cli.arguments(changed)

    def test_source_order_authenticates_before_keys_and_publishes_receipt_last(self):
        source = (ROOT / "catchplate" / "authority_local_artifacts.py").read_text()
        tree = ast.parse(source)
        method = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "produce")
        text = ast.get_source_segment(source, method)
        self.assertLess(text.index("authenticate_upstream("), text.index("io.signing_key("))
        self.assertLess(text.index("measure.measure_tree("), text.index("io.signing_key("))
        self.assertLess(text.index("spec.verify_signed_artifact_package("), text.index("publish(output_directory_fd"))
        self.assertLess(text.index("OUTPUTS[0]"), text.index("OUTPUTS[1]"))
        self.assertNotIn("currentGenerationSequence\"] =", text)


if __name__ == "__main__":
    unittest.main()
