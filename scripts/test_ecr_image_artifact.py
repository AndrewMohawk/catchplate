#!/usr/bin/env python3
"""Pure byte-validation component tests, not custody or ECR upload acceptance.

Tiny synthetic image descriptors and real caller-owned streams exercise the
production verifier. Config/layer payloads are opaque: these tests do not claim
that a container can run, an artifact is immutable, or an upload is approved.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_image_artifact as artifact


OCI = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_TAR = "application/vnd.oci.image.layer.v1.tar"
DOCKER = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
CONFIG = b'{"architecture":"amd64","os":"linux"}'
LAYER = b"synthetic layer\x00\xff\r\n"
SECOND_LAYER = b"second synthetic layer\n"


def prohibit_network(event, _args):
    if event.startswith("socket."):
        raise PermissionError("artifact tests forbid sockets and DNS")


sys.addaudithook(prohibit_network)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptor(media, data):
    return {"mediaType": media, "digest": digest(data), "size": len(data)}


def manifest(*, docker=False, config=CONFIG, layers=(LAYER,)):
    return {
        "schemaVersion": 2,
        "mediaType": DOCKER if docker else OCI,
        "config": descriptor(DOCKER_CONFIG if docker else OCI_CONFIG, config),
        "layers": [descriptor(DOCKER_GZIP if docker else OCI_TAR, row)
                   for row in layers],
    }


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class Reader:
    """Actual bytes with observed calls; no seek/close is allowed by the API."""

    def __init__(self, data, *, piece=None, hook=None):
        self.buffer = io.BytesIO(data)
        self.piece = piece
        self.hook = hook
        self.calls = []

    def read(self, count):
        if type(count) is not int or count <= 0:
            raise AssertionError("verifier requested an unbounded/invalid read")
        self.calls.append(count)
        if self.hook:
            self.hook(self, count)
        return self.buffer.read(min(count, self.piece) if self.piece else count)

    def close(self):
        raise AssertionError("verifier closed a caller-owned reader")

    def seek(self, *_args):
        raise AssertionError("verifier repositioned a caller-owned reader")


def readers(*payloads):
    return {digest(data): Reader(data) for data in payloads}


class EcrImageArtifactTests(unittest.TestCase):
    def refused(self, raw, blobs, *, message=None):
        with self.assertRaises(artifact.ImageArtifactError) as caught:
            artifact.verify_image(raw, blobs)
        if message is not None:
            self.assertEqual(str(caught.exception), message)
        self.assertNotIn("SECRET-CANARY", str(caught.exception))
        return caught.exception

    def test_shared_literal_vector_and_original_manifest_commitment(self):
        path = Path(__file__).parent / "fixtures/ecr_image_artifact_v1.json"
        vector = json.loads(path.read_bytes())
        self.assertEqual(vector["schema"], "serverware.ecrImageArtifactVector/v1")
        raw = vector["manifest"].encode()
        supplied = {row["digest"]: Reader(row["utf8"].encode()) for row in vector["blobs"]}
        for key, reader in supplied.items():
            self.assertEqual(key, digest(reader.buffer.getvalue()))
        result = artifact.verify_image(raw, supplied)
        expected = vector["expected_commitment"]
        # The checked-in literal was produced independently, not by this verifier.
        canonical = json.dumps(expected, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode()
        self.assertEqual(canonical, vector["expected_commitment_json"].encode())
        self.assertEqual(digest(canonical), vector["expected_commitment_sha256"])
        self.assertEqual(result.commitment(), expected)
        self.assertEqual(result.commitment_sha256,
                         "sha256:a433807a418a8d5bb2674e45321ce12b8983f21e4198ed2f386bc540fe311973")
        self.assertEqual(result.manifest_bytes, raw)
        self.assertEqual((result.manifest.size, result.total_blob_bytes), (735, 18))
        self.assertEqual([row.digest for row in result.layers],
                         [expected["layers"][0]["digest"]] * 2)
        self.assertEqual([row.digest for row in result.blobs], sorted(supplied))
        self.assertEqual([reader.calls for reader in supplied.values()], [[2, 1], [16, 1]])
        changed = artifact.verify_image(encoded(json.loads(raw)),
            {row["digest"]: Reader(row["utf8"].encode()) for row in vector["blobs"]})
        self.assertNotEqual(changed.manifest.digest, result.manifest.digest)
        self.assertNotEqual(changed.commitment_sha256, result.commitment_sha256)

    def test_parse_only_is_not_verified_and_projection_is_detached(self):
        value = manifest()
        value["annotations"] = {"test": "SECRET-CANARY"}
        raw = encoded(value)
        parsed = artifact.parse_manifest(raw)
        self.assertIs(type(parsed), artifact.ManifestDescription)
        self.assertFalse(hasattr(parsed, "commitment"))
        self.assertFalse(hasattr(parsed, "commitment_sha256"))
        self.refused(raw, {})  # A manifest and digest claims are not blob bytes.
        for cls in (artifact.ManifestDescription, artifact.VerifiedImage):
            with self.assertRaises(artifact.ImageArtifactError):
                cls()
        forged = object.__new__(artifact.VerifiedImage)
        with self.assertRaises(artifact.ImageArtifactError):
            forged.commitment()
        result = artifact.verify_image(raw, readers(CONFIG, LAYER))
        self.assertIs(type(result), artifact.VerifiedImage)
        self.assertEqual(set(result.commitment()), {
            "schema", "manifest", "config", "layers", "blobs", "total_blob_bytes"})
        # No clock, expiry, custody, authorization or approval is inferred.
        self.assertFalse(hasattr(result, "expires_at"))
        public = result.commitment()
        public["layers"].clear()
        public["config"]["size"] = 0
        self.assertEqual(len(result.commitment()["layers"]), 1)
        self.assertEqual(result.config.size, len(CONFIG))
        for obj, attr in ((result, "manifest_bytes"), (result.config, "size"),
                          (result.blobs[0], "size"), (parsed, "manifest_bytes")):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, attr, None)
        self.assertNotIn("SECRET-CANARY", repr(result) + repr(parsed))

    def test_closed_media_types_and_opaque_config(self):
        for docker, media in ((False, OCI_TAR), (False, OCI_TAR + "+gzip"),
                              (False, OCI_TAR + "+zstd"), (True, DOCKER_GZIP)):
            with self.subTest(docker=docker, media=media):
                config = b"\xffnot-config-JSON\x00"
                value = manifest(docker=docker, config=config)
                value["layers"][0]["mediaType"] = media
                result = artifact.verify_image(encoded(value), readers(config, LAYER))
                self.assertEqual(result.config.digest, digest(config))
                self.assertEqual(result.layers[0].media_type, media)
        value = manifest(layers=())
        self.assertEqual(artifact.verify_image(encoded(value), readers(CONFIG)).layers, ())
        for location, wrong in (
            ("root", "application/vnd.oci.image.index.v1+json"),
            ("root", "application/vnd.docker.distribution.manifest.list.v2+json"),
            ("config", DOCKER_CONFIG), ("layer", DOCKER_GZIP),
            ("layer", "application/vnd.oci.image.layer.nondistributable.v1.tar"),
            ("layer", OCI_TAR + "+unknown"), ("layer", OCI_TAR.upper())):
            with self.subTest(location=location, wrong=wrong):
                value = manifest()
                row = value if location == "root" else (
                    value["config"] if location == "config" else value["layers"][0])
                row["mediaType"] = wrong
                self.refused(encoded(value), readers(CONFIG, LAYER))
        value = manifest(docker=True)
        value["layers"][0]["mediaType"] = OCI_TAR
        self.refused(encoded(value), readers(CONFIG, LAYER))

    def test_repeated_layers_verify_once_and_input_roster_is_snapshotted(self):
        value = manifest(layers=(LAYER, SECOND_LAYER, LAYER))
        supplied = readers(CONFIG, LAYER, SECOND_LAYER)
        retained = dict(supplied)
        for reader in supplied.values():
            reader.hook = lambda *_args: supplied.clear()
        result = artifact.verify_image(encoded(value), supplied)
        self.assertEqual(supplied, {})
        self.assertEqual([row.digest for row in result.layers],
                         [digest(LAYER), digest(SECOND_LAYER), digest(LAYER)])
        self.assertEqual(result.total_blob_bytes, len(CONFIG) + len(LAYER) + len(SECOND_LAYER))
        self.assertEqual(len(result.blobs), 3)
        for reader in retained.values():
            self.assertEqual(reader.calls, [len(reader.buffer.getvalue()), 1])

    def test_missing_extra_invalid_roster_and_conflicting_descriptors(self):
        raw = encoded(manifest())
        base = readers(CONFIG, LAYER)
        invalid = [None, list(base.items()), tuple(base.items()) * 2, {},
                   {digest(CONFIG): base[digest(CONFIG)]},
                   {**base, digest(SECOND_LAYER): Reader(SECOND_LAYER)},
                   {**base, "SHA256:" + "a" * 64: Reader(b"x")},
                   {digest(CONFIG): object(), digest(LAYER): Reader(LAYER)}]
        class DictSubclass(dict):
            pass
        invalid.append(DictSubclass(base))
        for supplied in invalid:
            with self.subTest(kind=type(supplied).__name__):
                self.refused(raw, supplied)
        self.assertTrue(all(not row.calls for row in base.values()))
        for field, wrong in (("size", len(LAYER) + 1), ("mediaType", OCI_TAR + "+gzip"),
                             ("annotations", {"different": "claim"})):
            value = manifest(layers=(LAYER, LAYER))
            value["layers"][1][field] = wrong
            supplied = readers(CONFIG, LAYER)
            self.refused(encoded(value), supplied)
            self.assertTrue(all(not row.calls for row in supplied.values()))
        # Identical bytes cannot be both config and layer with differing media.
        self.refused(encoded(manifest(config=LAYER)), readers(LAYER))

    def test_strict_json_closed_fields_depth_and_node_bounds(self):
        raw = encoded(manifest())
        invalid = [b"", b"\xff", b"\xef\xbb\xbf" + raw, raw + b"{}", b"[]", b"null",
            raw.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2'),
            raw.replace(b'"size":', b'"size":1,"size":', 1),
            b"[" * 9 + b"0" + b"]" * 9,
            b"[" + b"0," * 20001 + b"0]", raw[:-1], raw + b"\x00"]
        for number in (b"NaN", b"Infinity", b"-Infinity", b"2.0", b"2e0", b"true", b"false"):
            invalid.append(raw.replace(b'"schemaVersion":2', b'"schemaVersion":' + number))
        for document in invalid:
            with self.subTest(raw=document[:50]):
                self.refused(document, readers(CONFIG, LAYER), message="ECR image artifact unavailable")
        for field, item in (("expiresAt", "2099-01-01T00:00:00Z"), ("subject", {}),
                            ("artifactType", "unknown"), ("urls", [])):
            self.refused(encoded({**manifest(), field: item}), readers(CONFIG, LAYER))
        for field in ("schemaVersion", "mediaType", "config", "layers"):
            value = manifest()
            del value[field]
            self.refused(encoded(value), readers(CONFIG, LAYER))
        for document in (raw.decode(), bytearray(raw), memoryview(raw)):
            self.refused(document, readers(CONFIG, LAYER))
        # Braces and escaped quotes inside strings are not structural depth.
        value = manifest()
        value["annotations"] = {"text": '[' * 32 + '\\"}' * 12}
        artifact.verify_image(encoded(value), readers(CONFIG, LAYER))

    def test_integer_digest_and_unallocated_aggregate_refusals(self):
        self.assertEqual((artifact.MAX_MANIFEST_BYTES, artifact.MAX_CONFIG_BYTES,
            artifact.MAX_BLOB_BYTES, artifact.MAX_TOTAL_BYTES, artifact.MAX_LAYERS,
            artifact.READ_CHUNK_BYTES, artifact.MAX_READ_CALLS_PER_BLOB),
            (4 * 1024**2, 4 * 1024**2, 512 * 1024**2, 1024**3, 128, 1024**2, 8192))
        mutations = [("size", value) for value in
                     (True, False, 0, -1, 1.0, "1", None, 512 * 1024**2 + 1, 10**100)]
        mutations += [("digest", value) for value in
            (True, "sha256:" + "A" * 64, "sha256:" + "a" * 63,
             "sha256:" + "a" * 64 + "\n", "sha512:" + "a" * 64)]
        mutations += [("urls", ["https://not-contacted.invalid/blob"]), ("data", "eA==")]
        for field, wrong in mutations:
            value = manifest()
            value["layers"][0][field] = wrong
            supplied = readers(CONFIG, LAYER)
            self.refused(encoded(value), supplied)
            self.assertTrue(all(not row.calls for row in supplied.values()))
        value = manifest()
        value["config"]["size"] = 4 * 1024**2 + 1
        self.refused(encoded(value), readers(CONFIG, LAYER))
        value = manifest()
        value["layers"] = [{"mediaType": OCI_TAR, "digest": "sha256:" + char * 64,
                            "size": 512 * 1024**2} for char in "ab"]
        supplied = {digest(CONFIG): Reader(CONFIG), **{"sha256:" + char * 64: Reader(b"x") for char in "ab"}}
        self.refused(encoded(value), supplied)  # Unique total exceeds 1 GiB; no large allocation.
        self.assertTrue(all(not row.calls for row in supplied.values()))

    def test_annotation_limits_and_semantic_descriptor_equality(self):
        allowed = {"!" * 256: "λ" * 2048, "empty": "", "control": "\n\t\x01"}
        value = manifest(layers=(LAYER, LAYER))
        value["annotations"] = allowed
        for row in (value["config"], *value["layers"]):
            row["annotations"] = {"same": "value"}
        artifact.verify_image(encoded(value), readers(CONFIG, LAYER))
        invalid = [{"": ""}, {"a" * 257: ""}, {"two words": ""}, {"é": ""},
                   {"a\x7f": ""}, {"a": "\0"}, {"a": "x" * 4097},
                   {"a": "λ" * 2049}, {"a": True}, {"a": 1}, {"a": []},
                   {str(index): "" for index in range(33)}, [], None]
        for annotations in invalid:
            with self.subTest(annotations=repr(annotations)[:40]):
                value = manifest()
                value["annotations"] = annotations
                self.refused(encoded(value), readers(CONFIG, LAYER))
        value = manifest()
        value["annotations"] = {"key": "\ud800"}
        self.refused(json.dumps(value).encode(), readers(CONFIG, LAYER))
        for location in ("root", "config", "layer"):
            value = manifest(docker=True)
            row = value if location == "root" else (value["config"] if location == "config" else value["layers"][0])
            row["annotations"] = {}
            self.refused(encoded(value), readers(CONFIG, LAYER))

    def test_partial_reads_existing_position_and_exact_eof(self):
        value = manifest()
        supplied = {digest(data): Reader(b"prefix" + data, piece=3) for data in (CONFIG, LAYER)}
        for reader in supplied.values():
            self.assertEqual(reader.buffer.read(6), b"prefix")
        result = artifact.verify_image(encoded(value), supplied)
        self.assertEqual(result.config.digest, digest(CONFIG))
        self.assertEqual(result.layers[0].digest, digest(LAYER))
        for reader in supplied.values():
            self.assertGreater(len(reader.calls), 2)
            self.assertEqual(reader.calls[-1], 1)
            self.assertTrue(all(0 < count <= 1024**2 for count in reader.calls))
            self.assertFalse(reader.buffer.closed)

    def test_reader_truncation_overreturn_types_exceptions_and_wrong_hash(self):
        raw = encoded(manifest(config=b"abc", layers=()))
        class Scripted:
            def __init__(self, results):
                self.results = iter(results)
            def read(self, _count):
                result = next(self.results)
                if isinstance(result, BaseException):
                    raise result
                return result
        cases = ([b""], [b"a", b""], [b"abcd"], ["abc"], [bytearray(b"abc")],
                 [memoryview(b"abc")], [None], [b"abc", b"x"], [b"abc", ""],
                 [b"abc", bytearray()], [b"abd", b""],
                 [OSError("SECRET-CANARY")], [b"abc", RuntimeError("SECRET-CANARY")])
        for outputs in cases:
            with self.subTest(outputs=repr(outputs)[:45]):
                self.refused(raw, {digest(b"abc"): Scripted(outputs)},
                             message="ECR image artifact unavailable")
        # Reusing one stream for distinct content cannot count as two verified blobs.
        shared = Reader(CONFIG)
        self.refused(encoded(manifest()), {digest(CONFIG): shared, digest(LAYER): shared})

    def test_cancellation_propagates_at_body_and_final_eof(self):
        class Cancelled(BaseException):
            pass
        for at in (1, 2):
            cancelled = Cancelled("SECRET-CANARY")
            def hook(reader, _count):
                if len(reader.calls) == at:
                    raise cancelled
            stream = Reader(CONFIG, hook=hook)
            with self.assertRaises(Cancelled) as caught:
                artifact.verify_image(encoded(manifest(layers=())), {digest(CONFIG): stream})
            self.assertIs(caught.exception, cancelled)
            self.assertEqual(len(stream.calls), at)
            self.assertFalse(stream.buffer.closed)

    def test_inclusive_size_layer_and_aggregate_limits_without_large_bodies(self):
        value = manifest(config=b"ab", layers=(b"xyz", b"xyz"))
        raw = encoded(value)
        limits = {"MAX_MANIFEST_BYTES": len(raw), "MAX_CONFIG_BYTES": 2,
                  "MAX_BLOB_BYTES": 3, "MAX_TOTAL_BYTES": 5, "MAX_LAYERS": 2}
        with patch.multiple(artifact, **limits):
            result = artifact.verify_image(raw, readers(b"ab", b"xyz"))
            self.assertEqual(result.total_blob_bytes, 5)  # Repeats not double counted.
        for name, limit in limits.items():
            with self.subTest(limit=name), patch.object(artifact, name, limit - 1):
                supplied = readers(b"ab", b"xyz")
                self.refused(raw, supplied)
                self.assertTrue(all(not row.calls for row in supplied.values()))
        value = manifest(layers=(LAYER,) * 128)
        result = artifact.verify_image(encoded(value), readers(CONFIG, LAYER))
        self.assertEqual(len(result.layers), 128)
        value["layers"].append(deepcopy(value["layers"][0]))
        self.refused(encoded(value), readers(CONFIG, LAYER))

    def test_chunk_and_total_read_call_limits_include_eof(self):
        raw = encoded(manifest(config=b"abcdef", layers=()))
        with patch.object(artifact, "READ_CHUNK_BYTES", 2):
            stream = Reader(b"abcdef")
            artifact.verify_image(raw, {digest(b"abcdef"): stream})
            self.assertEqual(stream.calls, [2, 2, 2, 1])
        with patch.object(artifact, "MAX_READ_CALLS_PER_BLOB", 4):
            stream = Reader(b"abc", piece=1)
            artifact.verify_image(encoded(manifest(config=b"abc", layers=())), {digest(b"abc"): stream})
            self.assertEqual(stream.calls, [3, 2, 1, 1])
            stream = Reader(b"abcd", piece=1)
            self.refused(encoded(manifest(config=b"abcd", layers=())), {digest(b"abcd"): stream})
            self.assertEqual(stream.calls, [4, 3, 2, 1])  # No over-budget EOF call.


if __name__ == "__main__":
    unittest.main()
