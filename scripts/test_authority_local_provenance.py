#!/usr/bin/env python3
"""Synthetic byte associations and real bounded file reads, not build evidence."""
from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_provenance as cli
from serverware import authority_local_provenance as local

DIGEST = "sha256:" + "1" * 64
NOW = 1_759_276_800_000_000_000


def fixture():
    """Truthful synthetic originals only; no constructed runtime/measurement owner."""
    contents = {"a.py": b"print('synthetic')\n", "b/data.txt": b"public fixture\n"}
    rows = []
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, raw in contents.items():
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            rows.append(dict(path=path, type="file", mode="100644", gitBlob=blob, bytes=len(raw), sha256=local.sha(raw)))
            member = tarfile.TarInfo(path); member.mode = 0o644; member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    archive_raw = archive_buffer.getvalue()
    tree = local._git_tree(rows)
    commit_raw = ("tree " + tree + "\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\n"
        "committer Fixture <fixture@example.invalid> 1700000000 +0000\n\nsynthetic test only\n").encode()
    commit_frame = b"commit " + str(len(commit_raw)).encode() + b"\0" + commit_raw
    commit = hashlib.sha1(commit_frame).hexdigest()
    source_tree = dict(version="serverware.sourceTree/v3", identityMode="production-commit",
        productionReleaseEligible=True, commit=commit, commitTimestamp="1700000000", gitTree=tree, files=rows)
    tree_digest = local.sha(local.spec.canonical_json_bytes(source_tree))
    stem = "source-" + tree_digest[7:]
    verification = {}
    for name, suffix, text in (
        ("fileList", ".files", "".join(row["path"] + "\n" for row in rows)),
        ("fileHashes", ".files.sha256", "".join(row["sha256"][7:] + "  " + row["path"] + "\n" for row in rows)),
        ("fileModes", ".files.mode", "".join("644  " + row["path"] + "\n" for row in rows))):
        raw = text.encode(); verification[name] = dict(name=stem + suffix, bytes=len(raw), sha256=local.sha(raw))
    source = dict(apiVersion="serverware.sourceArchive/v1", identityMode="production-commit",
        productionReleaseEligible=True, repository="https://github.com/example/private-deployment",
        commit=commit, commitTimestamp="1700000000", gitTree=tree, sourceTreeDigest=tree_digest,
        sourceTreeManifest=source_tree, archive=dict(format="tar-ustar-deterministic-v1",
            name=stem + ".tar", bytes=len(archive_raw), sha256=local.sha(archive_raw)), verification=verification,
        reconstruction=dict(requiresExactCommit=True, trackedFilesOnly=True, mtime=0, uid=0, gid=0,
                            entryOrder="sourceTreeManifest.files order"))
    source_raw = local.spec.canonical_json_bytes(source) + b"\n"
    metadata = dict(revision=commit, source=source["repository"], source_date_epoch=source["commitTimestamp"],
        source_tree_digest=tree_digest, source_archive_digest=local.sha(archive_raw),
        source_manifest_digest=local.sha(source_raw), source_identity_mode="production-commit", production_release_eligible=True,
        source_contract=dict(source, digest=tree_digest,
            manifest=dict(name=stem + ".manifest.json", sha256=local.sha(source_raw), bytes=len(source_raw)),
            archivePath="ignored/historical-source.tar", manifestPath="ignored/historical-manifest.json", verificationPaths={}))
    layer_raw = b"synthetic OCI blob; not claimed to be an executable image"
    config = dict(os="linux", architecture="amd64", rootfs=dict(type="layers", diff_ids=[local.sha(layer_raw)]),
        config=dict(Labels={"org.opencontainers.image.revision": commit,
            "dev.serverware.source_tree_digest": tree_digest, "dev.serverware.source_archive_digest": local.sha(archive_raw),
            "dev.serverware.source_manifest_digest": local.sha(source_raw), "dev.serverware.source_identity_mode": "production-commit",
            "dev.serverware.production_release_eligible": "true"}))
    config_raw = local.spec.canonical_json_bytes(config)
    manifest = dict(schemaVersion=2, mediaType=local.OCI_MANIFEST,
        config=dict(mediaType=local.OCI_CONFIG, digest=local.sha(config_raw), size=len(config_raw)),
        layers=[dict(mediaType="application/vnd.oci.image.layer.v1.tar", digest=local.sha(layer_raw), size=len(layer_raw))])
    report = dict(apiVersion="serverware.productionImagesBuild/v2", kind="ProductionImagesBuild", ok=True,
        identity_mode="production-commit", production_release_eligible=True, generated_at_unix=NOW // 1_000_000_000 - 1,
        metadata=metadata, images=[dict(service="serverware-control", dockerfile="Dockerfile.production",
            tag="synthetic:test", image_id=local.sha(config_raw))], no_shell={}, publish_requirement="synthetic fixture, not observed execution")
    originals = dict(report=(json.dumps(report, indent=2, sort_keys=True) + "\n").encode(), sourceManifest=source_raw,
        gitCommit=commit_raw, ociConfig=config_raw, ociManifest=local.spec.canonical_json_bytes(manifest))
    objects = dict(report="report.json", sourceManifest="source.json", sourceArchive="source.tar", gitCommit="commit.object",
        ociConfig="config.json", ociManifest="manifest.json", layers=["layer.tar"])
    all_raw = {objects[name]: raw for name, raw in originals.items()}
    all_raw.update({objects["sourceArchive"]: archive_raw, objects["layers"][0]: layer_raw})
    files = [dict(path=path, kind="provenance" if path == objects["report"] else "data",
                  mode=0o400, uid=0, gid=0, size=len(raw), sha256=local.sha(raw)) for path, raw in sorted(all_raw.items())]
    measured = dict(files=files, treeDigest=local.spec.domain_digest(local.spec.SOURCE_TREE_DIGEST_DOMAIN, local.spec.canonical_json_bytes(files)))
    selected = dict(schema=local.APPROVAL_SCHEMA, purpose=local.PURPOSE, trustSha256=DIGEST,
        signerKeyId="local-provenance-test", sourceRoot=dict(runtimePath="/synthetic/frozen", device=1, inode=2),
        treeDigest=measured["treeDigest"], files=[{key: row[key] for key in local.measure.FIELDS} for row in files],
        objects=objects, imageService="serverware-control", bootIdDigest=DIGEST,
        issuedAtBoottimeNs=100, deadlineBoottimeNs=200, issuedAtUnixNanos=NOW, expiresAtUnixNanos=NOW + 1_000_000_000)
    return selected, measured, originals, archive_raw


def repin(selected, measured, originals, name, raw):
    originals[name] = raw
    row = next(row for row in measured["files"] if row["path"] == selected["objects"][name])
    row.update(size=len(raw), sha256=local.sha(raw))
    measured["treeDigest"] = local.spec.domain_digest(local.spec.SOURCE_TREE_DIGEST_DOMAIN, local.spec.canonical_json_bytes(measured["files"]))
    selected["treeDigest"] = measured["treeDigest"]


class LocalProvenanceTests(unittest.TestCase):
    def test_closed_approval_and_fixed_cli(self):
        selected, _, _, _ = fixture()
        self.assertEqual(local.approval(local.spec.canonical_json_bytes(selected)), selected)
        for name, value in (("purpose", "slsa"), ("deadlineBoottimeNs", 100 + local.MAX_OPERATION_NS + 1),
                            ("imageService", "arbitrary"), ("renew", True)):
            wrong = dict(selected, **{name: value})
            with self.subTest(name=name), self.assertRaises(ValueError):
                local.approval(local.spec.canonical_json_bytes(wrong))
        args = ["--approval-fd", "3", "--approval-sha256", DIGEST, "--trust-fd", "4", "--trust-sha256", DIGEST,
                "--source-root-fd", "5", "--signing-key-fd", "6"]
        self.assertEqual(cli.arguments(args)["signing_key_fd"], 6)
        for wrong in (args + ["--key", "secret"], [args[0], "03", *args[2:]], []):
            with self.assertRaises(ValueError):
                cli.arguments(wrong)

    def test_pure_association_uses_existing_signature_and_exact_commit_frame(self):
        selected, measured, originals, _ = fixture()
        payload, source = local.association(selected, measured, originals)
        self.assertEqual(payload["predicateType"], local.PREDICATE)
        self.assertEqual(payload["sourceTreeDigest"], measured["treeDigest"])
        self.assertEqual(payload["sourceCommitDigest"], local.sha(b"commit " + str(len(originals["gitCommit"])).encode() + b"\0" + originals["gitCommit"]))
        self.assertNotEqual(payload["sourceTreeDigest"], source["sourceTreeDigest"])
        unsigned = {key: value for key, value in payload.items() if key != "statementDigest"}
        self.assertEqual(payload["statementDigest"], local.spec.domain_digest(local.spec.PROVENANCE_PAYLOAD_DIGEST_DOMAIN, local.spec.canonical_json_bytes(unsigned)))
        private = Ed25519PrivateKey.generate()
        message = local.spec._signature_message(local.spec.PROVENANCE_SIGNATURE_DOMAIN, payload)
        private.public_key().verify(private.sign(message), message)

    def test_real_archive_read_refuses_changed_member_or_extra_tail(self):
        selected, measured, originals, raw = fixture()
        _, source = local.association(selected, measured, originals)
        for altered in (None, raw[:512] + b"X" + raw[513:], raw + b"extra"):
            with tempfile.TemporaryFile() as stream:
                stream.write(raw if altered is None else altered); stream.flush()
                checks = []
                if altered is None:
                    local.verify_archive(stream.fileno(), source, check=lambda: checks.append(True))
                    self.assertGreater(len(checks), len(source["sourceTreeManifest"]["files"]))
                else:
                    with self.assertRaises(ValueError):
                        local.verify_archive(stream.fileno(), source, check=lambda: None)

    def test_commit_tree_timestamp_and_dirty_source_refuse(self):
        _, _, originals, _ = fixture()
        for name, value in (("commit", "0" * 40), ("gitTree", "0" * 40),
                            ("commitTimestamp", "1"), ("identityMode", "development-dirty-tree")):
            source = local.document(originals["sourceManifest"]); source[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                local.source_manifest(local.spec.canonical_json_bytes(source) + b"\n", originals["gitCommit"])

    def test_raw_export_dirty_report_and_wrong_image_refuse_even_when_repinned(self):
        for field, value in (("apiVersion", "serverware.engineeringRuntimeExport/v1"),
                             ("identity_mode", "development-dirty-tree"), ("production_release_eligible", False),
                             ("image", DIGEST), ("revision", "development-uncommitted")):
            selected, measured, originals, _ = fixture()
            report = local.document(originals["report"])
            if field == "image": report["images"][0]["image_id"] = value
            elif field == "revision": report["metadata"]["revision"] = value
            else: report[field] = value
            repin(selected, measured, originals, "report", local.spec.canonical_json_bytes(report))
            with self.subTest(field=field), self.assertRaises(ValueError):
                local.association(selected, measured, originals)

    def test_mismatched_oci_layers_and_config_source_labels_refuse(self):
        selected, measured, originals, _ = fixture()
        manifest = local.document(originals["ociManifest"])
        manifest["layers"][0]["digest"] = DIGEST
        repin(selected, measured, originals, "ociManifest", local.spec.canonical_json_bytes(manifest))
        with self.assertRaises(ValueError): local.association(selected, measured, originals)
        selected, measured, originals, _ = fixture()
        config = local.document(originals["ociConfig"])
        config["config"]["Labels"]["dev.serverware.source_manifest_digest"] = DIGEST
        config_raw = local.spec.canonical_json_bytes(config)
        repin(selected, measured, originals, "ociConfig", config_raw)
        manifest = local.document(originals["ociManifest"])
        manifest["config"].update(digest=local.sha(config_raw), size=len(config_raw))
        repin(selected, measured, originals, "ociManifest", local.spec.canonical_json_bytes(manifest))
        report = local.document(originals["report"]); report["images"][0]["image_id"] = local.sha(config_raw)
        repin(selected, measured, originals, "report", local.spec.canonical_json_bytes(report))
        with self.assertRaises(ValueError): local.association(selected, measured, originals)

    def test_duplicates_floats_and_noncanonical_approval_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}'):
            with self.assertRaises(ValueError): local.document(raw)
        selected, _, _, _ = fixture()
        with self.assertRaises(ValueError): local.approval(local.spec.canonical_json_bytes(selected) + b"\n")

    def test_source_order_keeps_measurement_archive_and_trust_before_key(self):
        # Static ordering only, not a fabricated successful retained owner.
        self.assertIs(local.LocalProvenanceIssuer.associate, local.association)
        tree = ast.parse(Path(local.__file__).read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalProvenanceIssuer")
        issue = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "issue")
        lines = {}
        for node in ast.walk(issue):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
                lines.setdefault(name, []).append(node.lineno)
        key_line = min(lines["signing_key"])
        for name in ("measure_tree", "associate", "verify_archive", "_verification_key"):
            self.assertLess(max(lines[name]), key_line)
        self.assertGreater(max(lines["check_originals"]), key_line)


if __name__ == "__main__":
    unittest.main()
