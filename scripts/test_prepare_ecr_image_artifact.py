#!/usr/bin/env python3
"""Actual local command checks; no AWS, approval or immutable-custody claim."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "scripts/fixtures/ecr_image_artifact_v1.json"


class PrepareEcrImageArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="serverware-ecr-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.source = self.parent / "source"
        self.blobs = self.source / "blobs" / "sha256"
        self.blobs.mkdir(parents=True, mode=0o700)
        self.vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        self.manifest_digest = self.vector["expected_commitment"]["manifest"]["digest"]
        self.manifest = self.vector["manifest"].encode("utf-8")
        (self.blobs / self.manifest_digest[7:]).write_bytes(self.manifest)
        for blob in self.vector["blobs"]:
            (self.blobs / blob["digest"][7:]).write_bytes(blob["utf8"].encode("utf-8"))
        self.destination = self.parent / "prepared"

    def command(self, *extra):
        return subprocess.run([sys.executable, "-B", "-m", "scripts.prepare_ecr_image_artifact",
            "--source", str(self.source), "--manifest-digest", self.manifest_digest,
            "--destination", str(self.destination), *extra], cwd=ROOT,
            env={key: value for key, value in os.environ.items()
                if key in {"PATH", "LANG", "LC_ALL"}},
            text=True, capture_output=True, timeout=20)

    def test_real_command_prepares_exact_unsigned_artifact(self):
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        marker = json.loads(result.stdout)
        self.assertEqual(marker, {
            "schema": "serverware.ecrArtifactStage/v1",
            "artifactSha256": self.vector["expected_commitment_sha256"],
            "manifestDigest": self.manifest_digest, "unsigned": True})
        self.assertEqual(json.loads((self.destination / "stage.json").read_bytes()), marker)
        self.assertEqual((self.destination / "manifest.json").read_bytes(), self.manifest)
        artifact = (self.destination / "artifact.json").read_bytes()
        self.assertEqual(artifact, self.vector["expected_commitment_json"].encode())
        self.assertEqual("sha256:" + hashlib.sha256(artifact).hexdigest(), marker["artifactSha256"])
        for blob in self.vector["blobs"]:
            self.assertEqual((self.destination / "blobs" / blob["digest"][7:]).read_bytes(),
                blob["utf8"].encode("utf-8"))
        self.assertNotIn("synthetic-layer", result.stdout)

    def test_existing_destination_is_not_overwritten_or_reused(self):
        self.destination.mkdir(mode=0o700)
        retained = self.destination / "existing-user-data"
        retained.write_bytes(b"preserve exactly")
        result = self.command()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("do not overwrite or retry", result.stderr)
        self.assertEqual(retained.read_bytes(), b"preserve exactly")
        self.assertEqual(list(self.destination.iterdir()), [retained])

    def test_changed_blob_never_produces_success_marker(self):
        blob = self.vector["blobs"][-1]
        (self.blobs / blob["digest"][7:]).write_bytes(b"wrong same size!")
        result = self.command()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertFalse((self.destination / "stage.json").exists())
        self.assertNotIn("wrong same size", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
