#!/usr/bin/env python3
"""Fresh-filesystem staging controls, not ECR publication or artifact approval.

Uses actual tiny OCI/Docker manifests, blob hashes, copies and readback. No
successful image verification is mocked. Fault injection is limited to I/O.
Private permissions are observed at return, not an immutability/custody claim.
"""
from contextlib import contextmanager
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_artifact_staging as staging


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Cancelled(BaseException):
    """Test-only caller cancellation; not an admission or authority token."""


class ImageFiles:
    """Independent wire fixture, deliberately not built with the image helper."""

    def __init__(self, base, docker=False, empty=False, payload_size=20):
        self.source = base / "source"
        self.destination = base / "staged"
        self.source.mkdir(mode=0o700)
        (self.source / "blobs").mkdir(mode=0o700)
        (self.source / "blobs" / "sha256").mkdir(mode=0o700)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as handle:
            raw = (b"tiny synthetic file\n" * (payload_size // 20 + 1))[:payload_size]
            entry = tarfile.TarInfo("hello.txt")
            entry.size = len(raw)
            entry.mode = 0o644
            handle.addfile(entry, io.BytesIO(raw))
        layer_tar = archive.getvalue()
        self.layer = gzip.compress(layer_tar, mtime=0) if docker else layer_tar
        self.config = canonical({"architecture": "amd64", "os": "linux", "rootfs": {
            "type": "layers", "diff_ids": [] if empty else [digest(layer_tar)]}}) + b"\n"
        self.manifest_type = ("application/vnd.docker.distribution.manifest.v2+json" if docker else
                              "application/vnd.oci.image.manifest.v1+json")
        self.config_type = ("application/vnd.docker.container.image.v1+json" if docker else
                            "application/vnd.oci.image.config.v1+json")
        self.layer_type = ("application/vnd.docker.image.rootfs.diff.tar.gzip" if docker else
                           "application/vnd.oci.image.layer.v1.tar")
        self.config_descriptor = {"mediaType": self.config_type, "digest": digest(self.config), "size": len(self.config)}
        self.layers = [] if empty else [{"mediaType": self.layer_type, "digest": digest(self.layer), "size": len(self.layer)}]
        self.manifest_value = {"schemaVersion": 2, "mediaType": self.manifest_type,
            "config": self.config_descriptor, "layers": self.layers}
        # Noncanonical whitespace is intentional: staging must retain bytes.
        self.manifest = (json.dumps(self.manifest_value, indent=2) + "\n").encode("ascii")
        self.manifest_digest = digest(self.manifest)
        self.blobs = {digest(self.config): self.config}
        if not empty:
            self.blobs[digest(self.layer)] = self.layer
        self.write_blob(self.manifest_digest, self.manifest)
        for name, raw in self.blobs.items():
            self.write_blob(name, raw)

    def path(self, name):
        return self.source / "blobs" / "sha256" / name.removeprefix("sha256:")

    def write_blob(self, name, raw):
        with self.path(name).open("xb") as handle:
            handle.write(raw)

    def stage(self):
        return staging.stage_artifact(str(self.source), str(self.destination), self.manifest_digest)

    def commitment(self):
        def descriptor(value):
            return {"media_type": value["mediaType"], "digest": value["digest"], "size": value["size"]}
        return {"schema": "serverware.ecrVerifiedImage/v1",
            "manifest": {"media_type": self.manifest_type, "digest": self.manifest_digest, "size": len(self.manifest)},
            "config": descriptor(self.config_descriptor), "layers": [descriptor(row) for row in self.layers],
            "blobs": [{"digest": name, "size": len(self.blobs[name])} for name in sorted(self.blobs)],
            "total_blob_bytes": sum(map(len, self.blobs.values()))}


class EcrArtifactStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ecr-staging-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(socket, "socket", side_effect=AssertionError("network forbidden")).start()
        patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")).start()
        patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")).start()

    def image(self, name, **kwargs):
        base = self.root / name
        base.mkdir(mode=0o700)
        return ImageFiles(base, **kwargs)

    def assert_incomplete(self, image):
        self.assertFalse((image.destination / "stage.json").exists())

    @contextmanager
    def on_read(self, target, action):
        """Inject once at a real selected-file pread, never replace its bytes."""
        real_pread = os.pread
        state = {"hits": 0}

        def read(descriptor, count, offset):
            if not state["hits"] and target.exists():
                held, named = os.fstat(descriptor), target.stat()
                if (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino):
                    state["hits"] += 1
                    action()
            return real_pread(descriptor, count, offset)

        with patch.object(staging.os, "pread", side_effect=read):
            yield state

    def assert_fixed_refusal(self, operation):
        with self.assertRaises(staging.ArtifactStagingError) as caught:
            operation()
        self.assertNotIn(str(self.root), str(caught.exception))
        return caught.exception

    def assert_complete(self, image, result):
        expected_artifact = image.commitment()
        marker = {"schema": "serverware.ecrArtifactStage/v1", "artifactSha256": digest(canonical(expected_artifact)),
            "manifestDigest": image.manifest_digest, "unsigned": True}
        self.assertEqual(type(result), dict)
        self.assertEqual(result, marker)
        self.assertEqual(json.loads((image.destination / "stage.json").read_bytes()), marker)
        self.assertEqual((image.destination / "manifest.json").read_bytes(), image.manifest)
        self.assertEqual(json.loads((image.destination / "artifact.json").read_bytes()), expected_artifact)
        self.assertEqual(set(path.name for path in image.destination.iterdir()),
                         {"manifest.json", "artifact.json", "blobs", "stage.json"})
        self.assertEqual(set(path.name for path in (image.destination / "blobs").iterdir()),
                         {name.removeprefix("sha256:") for name in image.blobs})
        for name, raw in image.blobs.items():
            destination = image.destination / "blobs" / name.removeprefix("sha256:")
            self.assertEqual(destination.read_bytes(), raw)
            self.assertEqual(digest(destination.read_bytes()), name)
            self.assertNotEqual(destination.stat().st_ino, image.path(name).stat().st_ino)
        for path in (image.destination, *image.destination.rglob("*")):
            info = path.lstat()
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertEqual(info.st_nlink, 1)

    def test_tiny_oci_docker_and_empty_images_preserve_exact_content(self):
        for label, kwargs in (("oci", {}), ("docker", {"docker": True}), ("empty", {"empty": True})):
            with self.subTest(label=label):
                image = self.image(label, **kwargs)
                source_bytes = {path.name: path.read_bytes() for path in (image.source / "blobs" / "sha256").iterdir()}
                # Other source blobs may coexist, but must not enter the exact
                # selected manifest's staged destination roster.
                image.write_blob(digest(b"unselected content"), b"unselected content")
                result = image.stage()
                self.assert_complete(image, result)
                for name, raw in source_bytes.items():
                    self.assertEqual((image.source / "blobs" / "sha256" / name).read_bytes(), raw)
                self.assertNotIn(digest(b"unselected content").removeprefix("sha256:"),
                                 {path.name for path in (image.destination / "blobs").iterdir()})
                self.assert_fixed_refusal(image.stage)
                self.assert_complete(image, result)

    def test_returned_marker_is_not_future_integrity_or_unsigned_approval(self):
        image = self.image("later-change")
        result = image.stage()
        self.assert_complete(image, result)
        self.assertIs(result["unsigned"], True)
        self.assertEqual(set(result), {"schema", "artifactSha256", "manifestDigest", "unsigned"})
        selected = image.destination / "blobs" / digest(image.config).removeprefix("sha256:")
        changed = selected.read_bytes() + b"x"
        selected.write_bytes(changed)
        self.assertNotEqual(digest(selected.read_bytes()), digest(image.config))
        # Staging has no existing-directory loader. A stale unsigned marker is
        # explicitly not future byte integrity; restaging cannot overwrite it.
        self.assert_fixed_refusal(image.stage)
        self.assertEqual(selected.read_bytes(), changed)
        self.assertEqual(json.loads((image.destination / "stage.json").read_bytes()), result)

    def test_existing_destination_is_never_reused_or_overwritten(self):
        for kind in ("empty", "populated", "symlink", "regular"):
            with self.subTest(kind=kind):
                image = self.image(kind)
                target = image.destination
                if kind == "symlink":
                    other = target.with_name("other")
                    other.mkdir(mode=0o700)
                    target.symlink_to(other, target_is_directory=True)
                elif kind == "regular":
                    target.write_bytes(b"unchanged file")
                else:
                    target.mkdir(mode=0o700)
                    if kind == "populated":
                        (target / "sentinel").write_bytes(b"unchanged directory")
                before = target.lstat()
                self.assert_fixed_refusal(image.stage)
                self.assertEqual((target.lstat().st_dev, target.lstat().st_ino), (before.st_dev, before.st_ino))
                if kind == "regular":
                    self.assertEqual(target.read_bytes(), b"unchanged file")
                elif kind == "populated":
                    self.assertEqual((target / "sentinel").read_bytes(), b"unchanged directory")
                else:
                    self.assertEqual(list(target.iterdir()), [])
                self.assert_incomplete(image)

    def test_noncanonical_paths_and_destination_ancestry_refused(self):
        image = self.image("paths")
        pairs = [("relative", str(image.destination)), (str(image.source), "relative"),
            (str(image.source) + "/.", str(image.destination)),
            (str(image.source) + "/../source", str(image.destination)),
            (str(image.source), str(image.destination) + "/.."),
            (str(image.source), str(image.source / "nested")),
            (str(image.source), str(image.source)),
            (str(image.source), str(image.destination.parent / "absent" / "child"))]
        for source, destination in pairs:
            with self.subTest(source=source, destination=destination):
                self.assert_fixed_refusal(lambda: staging.stage_artifact(source, destination, image.manifest_digest))
        alias = image.source.with_name("source-alias")
        alias.symlink_to(image.source, target_is_directory=True)
        self.assert_fixed_refusal(lambda: staging.stage_artifact(str(alias), str(image.destination), image.manifest_digest))
        alias_parent = self.root / "alias-parent"
        alias_parent.symlink_to(image.destination.parent, target_is_directory=True)
        self.assert_fixed_refusal(lambda: staging.stage_artifact(str(image.source), str(alias_parent / "staged"), image.manifest_digest))
        for name in ("../manifest", "sha256:../manifest", image.manifest_digest.upper(), "sha256:" + "a" * 63,
                     image.manifest_digest + "/extra", image.manifest_digest + "\n", None, True):
            self.assert_fixed_refusal(lambda: staging.stage_artifact(str(image.source), str(image.destination), name))
        self.assertFalse(image.destination.exists())

    def test_nonprivate_parent_and_nonregular_source_refused(self):
        image = self.image("parent-mode")
        image.destination.parent.chmod(0o755)
        self.assert_fixed_refusal(image.stage)
        self.assertFalse(image.destination.exists())
        for label, kind in (("manifest", "symlink"), ("config", "symlink"), ("layer", "symlink"),
                            ("manifest", "hardlink"), ("config", "hardlink"), ("layer", "hardlink"),
                            ("manifest", "directory"), ("config", "directory"),
                            ("manifest", "fifo"), ("config", "fifo")):
            with self.subTest(label=label, kind=kind):
                image = self.image(label + "-" + kind)
                name = {"manifest": image.manifest_digest, "config": digest(image.config), "layer": digest(image.layer)}[label]
                selected = image.path(name)
                if kind == "hardlink":
                    os.link(selected, selected.with_name("second-link"))
                else:
                    raw = selected.read_bytes()
                    selected.unlink()
                    if kind == "directory":
                        selected.mkdir(mode=0o700)
                    elif kind == "fifo":
                        os.mkfifo(selected, 0o600)
                    else:
                        ordinary = selected.with_name("ordinary")
                        ordinary.write_bytes(raw)
                        selected.symlink_to(ordinary)
                self.assert_fixed_refusal(image.stage)
                self.assert_incomplete(image)

    def test_missing_changed_and_oversized_selected_blobs_refused(self):
        for label in ("manifest", "config", "layer"):
            for mutation in ("missing", "changed", "extra-byte"):
                with self.subTest(label=label, mutation=mutation):
                    image = self.image(label + "-" + mutation)
                    name = {"manifest": image.manifest_digest, "config": digest(image.config), "layer": digest(image.layer)}[label]
                    selected = image.path(name)
                    if mutation == "missing":
                        selected.unlink()
                    else:
                        raw = selected.read_bytes()
                        selected.write_bytes(bytes([raw[0] ^ 1]) + raw[1:] if mutation == "changed" else raw + b"x")
                    self.assert_fixed_refusal(image.stage)
                    self.assert_incomplete(image)
        for label, maximum in (("manifest", 4 * 1024 * 1024), ("config", 4 * 1024 * 1024),
                               ("layer", 512 * 1024 * 1024)):
            image = self.image("oversized-" + label)
            name = {"manifest": image.manifest_digest, "config": digest(image.config), "layer": digest(image.layer)}[label]
            # Sparse test input; refusal must precede reading/allocating it.
            with image.path(name).open("r+b") as handle:
                handle.truncate(maximum + 1)
            self.assert_fixed_refusal(image.stage)
            self.assert_incomplete(image)

    def test_complete_marker_is_atomically_published_after_real_readback_and_sync(self):
        image = self.image("marker-order")
        real_pread, real_fsync, real_link = os.pread, os.fsync, os.link
        eof, synced, published = set(), set(), []

        def key(descriptor):
            info = os.fstat(descriptor)
            return info.st_dev, info.st_ino

        def read(descriptor, count, offset):
            self.assertLessEqual(count, 1024 * 1024)
            raw = real_pread(descriptor, count, offset)
            if raw == b"":
                eof.add(key(descriptor))
            return raw

        def sync(descriptor):
            real_fsync(descriptor)
            synced.add(key(descriptor))

        def link(source, destination, **kwargs):
            self.assertEqual((source, destination), ("stage.pending", "stage.json"))
            self.assertIs(kwargs.get("follow_symlinks"), False)
            self.assertFalse((image.destination / "stage.json").exists())
            self.assertEqual((image.destination / "manifest.json").read_bytes(), image.manifest)
            self.assertEqual((image.destination / "artifact.json").read_bytes(), canonical(image.commitment()))
            paths = [image.destination / "manifest.json", image.destination / "artifact.json",
                image.destination / "stage.pending", *(image.destination / "blobs" / name[7:] for name in image.blobs)]
            for path in paths:
                info = path.stat()
                self.assertIn((info.st_dev, info.st_ino), eof, "every selected staged file reached actual EOF")
                self.assertIn((info.st_dev, info.st_ino), synced, "every staged file was fsynced before publication")
            published.append(True)
            return real_link(source, destination, **kwargs)

        with patch.object(staging.os, "pread", side_effect=read), patch.object(staging.os, "fsync", side_effect=sync), \
                patch.object(staging.os, "link", side_effect=link):
            result = image.stage()
        self.assertEqual(published, [True])
        self.assert_complete(image, result)

    def test_bounded_short_writes_succeed_but_zero_error_and_cancellation_preserve_incomplete(self):
        image = self.image("short-write", payload_size=1024 * 1024 + 17)
        real_write = os.write
        writes = []

        def short_write(descriptor, raw):
            self.assertLessEqual(len(raw), 1024 * 1024)
            writes.append(len(raw))
            return real_write(descriptor, raw[:8191])

        with patch.object(staging.os, "write", side_effect=short_write):
            result = image.stage()
        self.assertGreater(len(writes), 100)
        self.assert_complete(image, result)
        for label, failure in (("zero", None), ("io-error", OSError("synthetic private path")),
                               ("cancelled", Cancelled("synthetic cancellation"))):
            with self.subTest(label=label):
                image = self.image(label)
                calls = []

                def interrupted(descriptor, raw):
                    calls.append(len(raw))
                    if len(calls) == 1:
                        return real_write(descriptor, raw[:1])
                    if failure is not None:
                        raise failure
                    return 0

                with patch.object(staging.os, "write", side_effect=interrupted):
                    if isinstance(failure, Cancelled):
                        with self.assertRaises(Cancelled) as caught:
                            image.stage()
                        self.assertIs(caught.exception, failure)
                    else:
                        error = self.assert_fixed_refusal(image.stage)
                        self.assertIs(error.completion_uncertain, False)
                        self.assertNotIn("synthetic private", str(error))
                self.assertEqual(len(calls), 2)
                self.assertTrue(image.destination.is_dir())
                self.assertEqual((image.destination / "manifest.json").read_bytes(), image.manifest[:1])
                self.assert_incomplete(image)

    def test_staged_readback_rejects_tamper_missing_extra_links_and_metadata(self):
        for kind in ("content", "missing", "extra", "symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                image = self.image("readback-" + kind)
                config = image.destination / "blobs" / digest(image.config)[7:]
                # Roster mutations occur during real artifact readback, after
                # referenced blob verification, so the later roster/currentness
                # guards—not a mock verifier—must refuse them.
                target = image.destination / "artifact.json" if kind in ("missing", "extra") else config

                def mutate():
                    if kind == "content":
                        original = config.read_bytes()
                        config.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                    elif kind == "missing":
                        config.unlink()
                    elif kind == "extra":
                        (image.destination / "blobs" / ("f" * 64)).write_bytes(b"not selected")
                    elif kind == "symlink":
                        config.unlink()
                        config.symlink_to(image.path(digest(image.config)))
                    elif kind == "hardlink":
                        os.link(config, image.destination / "extra-link")
                    else:
                        config.chmod(0o644)

                with self.on_read(target, mutate) as observation:
                    error = self.assert_fixed_refusal(image.stage)
                self.assertEqual(observation["hits"], 1)
                self.assertIs(error.completion_uncertain, False)
                self.assertTrue(image.destination.is_dir())
                self.assert_incomplete(image)

    def test_source_rename_and_inflight_read_error_or_cancellation_refuse(self):
        for kind in ("rename", "error", "cancelled"):
            with self.subTest(kind=kind):
                image = self.image("source-" + kind)
                failure = Cancelled("synthetic cancellation") if kind == "cancelled" else OSError("private synthetic detail")

                def mutate():
                    if kind == "rename":
                        image.source.rename(image.source.with_name("moved-source"))
                    else:
                        raise failure

                with self.on_read(image.path(digest(image.config)), mutate) as observation:
                    if kind == "cancelled":
                        with self.assertRaises(Cancelled) as caught:
                            image.stage()
                        self.assertIs(caught.exception, failure)
                    else:
                        error = self.assert_fixed_refusal(image.stage)
                        self.assertIs(error.completion_uncertain, False)
                self.assertEqual(observation["hits"], 1)
                self.assertTrue(image.destination.is_dir())
                self.assert_incomplete(image)

    def test_failed_atomic_publication_is_uncertain_and_never_overwrites_marker(self):
        for kind in ("link-failure", "racing-marker", "directory-sync"):
            with self.subTest(kind=kind):
                image = self.image(kind)
                real_link, real_fsync = os.link, os.fsync
                linked = []

                def link(source, destination, **kwargs):
                    if kind == "link-failure":
                        raise OSError("synthetic link failure")
                    if kind == "racing-marker":
                        (image.destination / "stage.json").write_bytes(b"existing marker must remain")
                    result = real_link(source, destination, **kwargs)
                    linked.append(True)
                    return result

                def sync(descriptor):
                    if kind == "directory-sync" and linked:
                        raise OSError("synthetic directory sync failure")
                    return real_fsync(descriptor)

                with patch.object(staging.os, "link", side_effect=link), patch.object(staging.os, "fsync", side_effect=sync):
                    error = self.assert_fixed_refusal(image.stage)
                self.assertIs(error.completion_uncertain, True)
                self.assertTrue((image.destination / "stage.pending").is_file())
                if kind == "link-failure":
                    self.assert_incomplete(image)
                elif kind == "racing-marker":
                    self.assertEqual((image.destination / "stage.json").read_bytes(), b"existing marker must remain")
                else:
                    self.assertEqual((image.destination / "stage.json").read_bytes(),
                                     (image.destination / "stage.pending").read_bytes())
                self.assert_fixed_refusal(image.stage)


if __name__ == "__main__":
    unittest.main()
