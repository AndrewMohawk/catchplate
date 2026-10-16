#!/usr/bin/env python3
"""Small actual files/streams and deterministic filesystem controls; no AWS."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_image_artifact as image
from serverware import operator_ecr_artifacts as store


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture(*, layer=b"small opaque synthetic layer", docker=False):
    config = b'{"architecture":"amd64","os":"linux"}\n'
    body = {"schemaVersion": 2,
        "mediaType": image.DOCKER_MANIFEST if docker else image.OCI_MANIFEST,
        "config": {"mediaType": image.DOCKER_CONFIG if docker else image.OCI_CONFIG,
            "digest": digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" if docker
            else "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}]}
    return (json.dumps(body, indent=3) + "\n").encode(), {digest(config): config, digest(layer): layer}


class Cancelled(BaseException):
    pass


class ArtifactStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="serverware-ecr-upload-test-",
            dir="/srv/catchplate-fast/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "artifacts"
        self.root.mkdir(mode=0o700)
        self.store = store.ArtifactStore(self.root)
        for name in ("socket", "create_connection", "getaddrinfo"):
            self.addCleanup(patch.stopall)
            patch.object(socket, name, side_effect=AssertionError("network forbidden")).start()

    def refuse(self, function):
        with self.assertRaises(store.ArtifactStoreError) as caught:
            function()
        self.assertIn(str(caught.exception), ("ECR artifact unavailable; preserve stage",
            "ECR artifact completion uncertain; preserve stage"))
        self.assertNotIn(str(self.base), str(caught.exception))
        return caught.exception

    def uploaded(self, *, docker=False, layer=b"small opaque synthetic layer"):
        stage = self.store.begin()
        manifest, blobs = fixture(docker=docker, layer=layer)
        description = self.store.write_manifest(stage, manifest)
        self.assertEqual(description.manifest_bytes, manifest)
        for name, raw in blobs.items():
            middle = max(1, len(raw) // 2)
            for offset, part in ((0, raw[:middle]), (middle, raw[middle:])):
                if part:
                    self.store.append_part(stage, name, offset, part)
        return stage, manifest, blobs

    def test_complete_original_bytes_private_marker_recapture(self):
        for docker in (False, True):
            with self.subTest(docker=docker):
                stage, manifest, blobs = self.uploaded(docker=docker)
                progress = self.store.summary(stage)
                self.assertEqual(progress["manifest_digest"], digest(manifest))
                self.assertTrue(all(row["complete"] and row["uploaded_bytes"] == row["size"]
                    for row in progress["blobs"]))
                with self.store.finalize(stage) as sealed:
                    self.assertEqual(sealed.image.manifest_bytes, manifest)
                    self.assertEqual(sealed.image.total_blob_bytes, sum(map(len, blobs.values())))
                    commitment = sealed.image.commitment_sha256
                    for name, raw in blobs.items():
                        self.assertEqual(sealed.read_blob(name, 0, len(raw)), raw)
                stage_path = self.root / stage
                self.assertEqual(set(path.name for path in stage_path.iterdir()),
                    {"manifest.json", "blobs", "artifact.json", "stage.json"})
                marker = json.loads((stage_path / "stage.json").read_bytes())
                self.assertEqual(marker, {"schema": "serverware.ecrArtifactStage/v1",
                    "artifactSha256": commitment, "manifestDigest": digest(manifest), "unsigned": True})
                for path in (stage_path, *stage_path.rglob("*")):
                    info = path.lstat()
                    self.assertEqual(info.st_uid, os.geteuid())
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if path.is_dir() else 0o600)
                    if path.is_file():
                        self.assertEqual(info.st_nlink, 1)
                restarted = store.ArtifactStore(self.root)
                with restarted.recapture(stage) as sealed:
                    self.assertEqual(sealed.image.commitment_sha256, commitment)
                self.refuse(lambda: self.store.finalize(stage))
                self.refuse(lambda: self.store.write_manifest(stage, manifest))
                name, raw = next(iter(blobs.items()))
                self.refuse(lambda: self.store.append_part(stage, name, 0, raw))

    def test_manifest_required_and_unreferenced_bytes_never_written(self):
        stage = self.store.begin()
        manifest, blobs = fixture()
        name, raw = next(iter(blobs.items()))
        self.refuse(lambda: self.store.append_part(stage, name, 0, raw))
        self.refuse(lambda: self.store.write_manifest(stage, b'{"unsupported":true}'))
        self.assertEqual(set(path.name for path in (self.root / stage).iterdir()), {"blobs"})
        self.store.write_manifest(stage, manifest)
        self.refuse(lambda: self.store.write_manifest(stage, manifest))
        self.refuse(lambda: self.store.append_part(stage, digest(b"not referenced"), 0, b"not referenced"))
        self.assertEqual(list((self.root / stage / "blobs").iterdir()), [])

    def test_chunk_exact_offset_reconciliation_and_no_replay(self):
        stage = self.store.begin()
        manifest, blobs = fixture()
        self.store.write_manifest(stage, manifest)
        name, raw = next(iter(blobs.items()))
        first = self.store.append_part(stage, name, 0, raw[:4])
        self.assertEqual(first, {"digest": name, "size": len(raw), "uploaded_bytes": 4, "complete": False})
        self.refuse(lambda: self.store.append_part(stage, name, 0, raw[:4]))
        self.refuse(lambda: self.store.append_part(stage, name, 3, raw[4:]))
        self.refuse(lambda: self.store.append_part(stage, name, 5, raw[4:]))
        self.refuse(lambda: self.store.append_part(stage, name, 4, b"a" * len(raw)))
        self.assertEqual(next(row for row in self.store.summary(stage)["blobs"]
            if row["digest"] == name)["uploaded_bytes"], 4)
        self.assertTrue(store.ArtifactStore(self.root).append_part(stage, name, 4, raw[4:])["complete"])
        self.refuse(lambda: self.store.append_part(stage, name, len(raw), b"x"))
        self.assertEqual((self.root / stage / "blobs" / name[7:]).read_bytes(), raw)

    def test_parts_bounded_and_large_blob_multiple_parts(self):
        layer = b"x" * (store.MAX_PART_BYTES + 1)
        manifest, blobs = fixture(layer=layer)
        stage = self.store.begin()
        self.store.write_manifest(stage, manifest)
        name = digest(layer)
        self.refuse(lambda: self.store.append_part(stage, name, 0, layer))
        for offset in (True, -1, 1.0, "0"):
            self.refuse(lambda offset=offset: self.store.append_part(stage, name, offset, b"x"))
        for raw in (b"", bytearray(b"x"), "x"):
            self.refuse(lambda raw=raw: self.store.append_part(stage, name, 0, raw))
        self.store.append_part(stage, name, 0, layer[:store.MAX_PART_BYTES])
        self.store.append_part(stage, name, store.MAX_PART_BYTES, layer[store.MAX_PART_BYTES:])
        config_name = next(key for key in blobs if key != name)
        self.store.append_part(stage, config_name, 0, blobs[config_name])
        with self.store.finalize(stage) as sealed:
            self.assertEqual(sealed.read_blob(name, store.MAX_PART_BYTES - 1, 2), b"xx")

    def test_wrong_hash_preserves_partial_and_prevents_finalize(self):
        stage = self.store.begin()
        manifest, blobs = fixture()
        self.store.write_manifest(stage, manifest)
        name, raw = next(iter(blobs.items()))
        wrong = b"!" + raw[1:]
        self.refuse(lambda: self.store.append_part(stage, name, 0, wrong))
        self.assertEqual((self.root / stage / "blobs" / (name[7:] + ".pending")).read_bytes(), wrong)
        self.assertFalse((self.root / stage / "blobs" / name[7:]).exists())
        self.refuse(lambda: self.store.finalize(stage))
        self.assertFalse((self.root / stage / "stage.json").exists())

    def test_missing_extra_and_unfinished_files_refuse_capture(self):
        stage = self.store.begin()
        manifest, _ = fixture()
        self.store.write_manifest(stage, manifest)
        self.refuse(lambda: self.store.finalize(stage))
        complete, _, _ = self.uploaded()
        extra = self.root / complete / "blobs" / "unexpected"
        extra.write_bytes(b"not part of image")
        extra.chmod(0o600)
        self.refuse(lambda: self.store.finalize(complete))
        self.refuse(lambda: self.store.summary(complete))

    def test_rehash_on_recapture_and_existing_sealed_bytes_unchanged(self):
        stage, _, blobs = self.uploaded()
        with self.store.finalize(stage) as sealed:
            name, raw = next(iter(blobs.items()))
            (self.root / stage / "blobs" / name[7:]).write_bytes(b"!" + raw[1:])
            self.assertEqual(sealed.read_blob(name, 0, len(raw)), raw)
            self.refuse(lambda: self.store.recapture(stage))

    def test_marker_and_commitment_are_checked_not_trusted(self):
        for filename in ("stage.json", "artifact.json"):
            with self.subTest(filename=filename):
                stage, _, _ = self.uploaded()
                self.store.finalize(stage).close()
                path = self.root / stage / filename
                path.write_bytes(path.read_bytes() + b" ")
                self.refuse(lambda: self.store.recapture(stage))

    def test_private_modes_and_hardlinks_refused(self):
        stage, _, blobs = self.uploaded()
        name, _ = next(iter(blobs.items()))
        path = self.root / stage / "blobs" / name[7:]
        path.chmod(0o644)
        self.refuse(lambda: self.store.finalize(stage))
        path.chmod(0o600)
        os.link(path, self.base / "outside-alias")
        self.refuse(lambda: self.store.finalize(stage))
        self.refuse(lambda: self.store.summary(stage))
        self.root.chmod(0o755)
        self.refuse(lambda: self.store.begin())
        self.refuse(lambda: store.ArtifactStore(self.root))
        self.root.chmod(0o700)

    def test_symlink_and_path_aliases_refused(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for path in (str(alias), str(self.root) + "/", str(self.root) + "/../artifacts", "relative"):
            self.refuse(lambda path=path: store.ArtifactStore(path))
        stage, _, blobs = self.uploaded()
        for bad in ("../" + stage, stage.upper(), stage + "/", "not-a-uuid", None):
            self.refuse(lambda bad=bad: self.store.describe(bad))
        name, _ = next(iter(blobs.items()))
        blob = self.root / stage / "blobs" / name[7:]
        original = self.base / "original-blob"
        blob.rename(original)
        blob.symlink_to(original)
        self.refuse(lambda: self.store.finalize(stage))
        stage_alias = str(uuid.uuid4())
        (self.root / stage_alias).symlink_to(self.root / stage, target_is_directory=True)
        self.refuse(lambda: self.store.describe(stage_alias))

    def test_root_replacement_not_adopted(self):
        self.root.rename(self.base / "previous-root")
        self.root.mkdir(mode=0o700)
        self.refuse(lambda: self.store.begin())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_admission_budget_includes_existing_failed_stages(self):
        self.refuse(lambda: store.ArtifactStore(self.root, max_stages=5))
        self.refuse(lambda: store.ArtifactStore(self.root, max_stages=True))
        ids = [self.store.begin() for _ in range(4)]
        self.assertEqual(len(set(ids)), 4)
        self.refuse(lambda: self.store.begin())
        self.refuse(lambda: store.ArtifactStore(self.root).begin())
        self.refuse(lambda: self.store.begin(ids[0]))
        self.assertEqual(len(list(self.root.iterdir())), 4)

    def test_new_stage_identity_and_cross_process_style_lock(self):
        stage = str(uuid.uuid4())
        self.assertEqual(self.store.begin(stage), stage)
        self.refuse(lambda: self.store.begin(stage))
        descriptor = os.open(self.root / stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            manifest, _ = fixture()
            self.refuse(lambda: store.ArtifactStore(self.root).write_manifest(stage, manifest))
            self.assertFalse((self.root / stage / "manifest.json").exists())
        finally:
            os.close(descriptor)

    def test_explicit_configured_root_readiness_never_creates_or_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(store.configuration_ready())
            self.refuse(store.configured_store)
        missing = self.base / "not-created"
        for value in ("", "relative", str(missing), str(self.root) + "/"):
            with patch.dict(os.environ, {store.ROOT_ENVIRONMENT_VARIABLE: value}, clear=True):
                self.assertFalse(store.configuration_ready())
                self.refuse(store.configured_store)
        self.assertFalse(missing.exists())
        with patch.dict(os.environ, {store.ROOT_ENVIRONMENT_VARIABLE: str(self.root)}, clear=True):
            self.assertTrue(store.configuration_ready())
            configured = store.configured_store()
            self.assertEqual(list(self.root.iterdir()), [])
            self.assertTrue((self.root / configured.begin()).is_dir())

    def test_partial_write_cancellation_retained_without_final_name(self):
        stage = self.store.begin()
        manifest, blobs = fixture()
        self.store.write_manifest(stage, manifest)
        name, raw = next(iter(blobs.items()))
        original_write = os.write
        calls = 0

        def interrupt(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(fd, data[:2])
            raise Cancelled()

        with patch.object(store.os, "write", side_effect=interrupt):
            with self.assertRaises(Cancelled):
                self.store.append_part(stage, name, 0, raw)
        self.assertEqual((self.root / stage / "blobs" / (name[7:] + ".pending")).read_bytes(), raw[:2])
        self.assertFalse((self.root / stage / "blobs" / name[7:]).exists())
        self.store.append_part(stage, name, 2, raw[2:])

    def test_marker_fsync_uncertainty_retains_files_and_closes_capture(self):
        stage, _, _ = self.uploaded()
        original_sync = os.fsync
        captured = []
        original_capture = store.custody.capture

        def capture(*args, **kwargs):
            held = original_capture(*args, **kwargs)
            captured.append(held)
            return held

        def sync(fd):
            if (self.root / stage / "stage.json").exists():
                raise OSError("private I/O diagnostic")
            return original_sync(fd)

        with patch.object(store.os, "fsync", side_effect=sync), \
                patch.object(store.custody, "capture", side_effect=capture):
            error = self.refuse(lambda: self.store.finalize(stage))
        self.assertTrue(error.completion_uncertain)
        self.assertTrue((self.root / stage / "stage.json").exists())
        self.assertTrue((self.root / stage / "stage.pending").exists())
        self.assertEqual(len(captured), 1)
        with self.assertRaises(store.custody.CustodyError):
            captured[0].image
        self.refuse(lambda: self.store.recapture(stage))


if __name__ == "__main__":
    unittest.main()
