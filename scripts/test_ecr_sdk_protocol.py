#!/usr/bin/env python3
"""Offline five-action ECR JSON protocol tests, not AWS or upload acceptance.

Inputs are independently assembled ordinary SDK-shaped JSON. No signer, SDK,
credential, network transport, upload state, approval or artifact custody runs.
The process-wide audit guard intentionally makes this a separate test process.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import base64
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest


def prohibit_network(event, _args):
    if event.startswith("socket."):
        raise PermissionError("offline ECR protocol tests forbid sockets and DNS")


sys.addaudithook(prohibit_network)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_sdk_protocol as protocol


REGISTRY, REGION, REPOSITORY = "123456789012", "us-east-1", "team/serverware-fixture"
UPLOAD = "00000000-0000-4000-8000-000000000001"
OTHER_UPLOAD = "11111111-1111-4111-8111-111111111111"
PART = b"PRIVATE-LAYER-CANARY\x00\xff\r\n"
MEDIA = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MEDIA = "application/vnd.docker.distribution.manifest.v2+json"
TAG = "fixture"
ACTIONS = ("BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart",
           "CompleteLayerUpload", "PutImage")


def sha(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


DIGEST, OTHER_DIGEST = sha(PART), sha(b"other synthetic layer")
MANIFEST = json.dumps({"schemaVersion": 2, "mediaType": MEDIA,
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 2,
               "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                "size": len(PART), "digest": DIGEST}],
    "annotations": {"fixture": "PRIVATE-MANIFEST-CANARY λ"}}, ensure_ascii=False, indent=2) + "\n"
MANIFEST_DIGEST = sha(MANIFEST.encode())


def encoded(value):
    # Ordinary json.dumps spacing/order, not a canonicalization used by the parser.
    return json.dumps(value, ensure_ascii=False).encode()


def request_value(action):
    fields = {
        "BatchCheckLayerAvailability": {"layerDigests": [DIGEST, OTHER_DIGEST]},
        "InitiateLayerUpload": {},
        "UploadLayerPart": {"uploadId": UPLOAD, "partFirstByte": 7,
            "partLastByte": 7 + len(PART) - 1, "layerPartBlob": base64.b64encode(PART).decode()},
        "CompleteLayerUpload": {"uploadId": UPLOAD, "layerDigests": [DIGEST]},
        "PutImage": {"imageManifest": MANIFEST, "imageManifestMediaType": MEDIA,
                     "imageTag": TAG, "imageDigest": MANIFEST_DIGEST},
    }[action]
    return {"registryId": REGISTRY, "repositoryName": REPOSITORY, **fields}


def response_value(action):
    # Raw HTTP API bodies, not parsed SDK dictionaries with ResponseMetadata.
    scope = {"registryId": REGISTRY, "repositoryName": REPOSITORY}
    return deepcopy({
        "BatchCheckLayerAvailability": {"layers": [
            {"layerDigest": DIGEST, "layerAvailability": "AVAILABLE", "layerSize": len(PART),
             "mediaType": "application/vnd.oci.image.layer.v1.tar"},
            {"layerDigest": OTHER_DIGEST, "layerAvailability": "UNAVAILABLE"}], "failures": []},
        "InitiateLayerUpload": {"uploadId": UPLOAD, "partSize": 5 * 1024**2},
        "UploadLayerPart": {**scope, "uploadId": UPLOAD, "lastByteReceived": 7 + len(PART) - 1},
        "CompleteLayerUpload": {**scope, "uploadId": UPLOAD, "layerDigest": DIGEST},
        "PutImage": {"image": {**scope, "imageId": {"imageDigest": MANIFEST_DIGEST, "imageTag": TAG},
            "imageManifest": MANIFEST, "imageManifestMediaType": MEDIA}},
    }[action])


class EcrSdkProtocolTests(unittest.TestCase):
    def setUp(self):
        self.scope = protocol.Scope(registry_id=REGISTRY, region=REGION, repository_name=REPOSITORY)

    def request(self, action, value=None, *, raw=None, scope=None):
        if raw is None:
            raw = encoded(request_value(action) if value is None else value)
        return protocol.parse_request(scope=self.scope if scope is None else scope, action=action, body=raw)

    def response(self, request, value=None, *, raw=None, status=200):
        if raw is None:
            raw = encoded(response_value(request.action) if value is None else value)
        return protocol.parse_response(request, status=status, body=raw)

    def refused(self, function, *args, **kwargs):
        with self.assertRaises(protocol.ProtocolError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "ECR SDK protocol unavailable")
        self.assertNotIn("CANARY", repr(caught.exception))

    def test_five_ordinary_requests_preserve_bytes_and_extract_only_expected_fields(self):
        defaults = {"layer_digests": (), "upload_id": None, "part_first_byte": None,
            "part_last_byte": None, "part_bytes": None, "image_manifest": None,
            "image_manifest_media_type": None, "image_tag": None, "image_digest": None}
        expected = (
            {"layer_digests": (DIGEST, OTHER_DIGEST)}, {},
            {"upload_id": UPLOAD, "part_first_byte": 7, "part_last_byte": 7 + len(PART) - 1,
             "part_bytes": PART},
            {"upload_id": UPLOAD, "layer_digests": (DIGEST,)},
            {"image_manifest": MANIFEST.encode(), "image_manifest_media_type": MEDIA,
             "image_tag": TAG, "image_digest": MANIFEST_DIGEST},
        )
        for action, extra in zip(ACTIONS, expected):
            with self.subTest(action=action):
                raw = encoded(request_value(action)) + b"\n "
                parsed = self.request(action, raw=raw)
                self.assertEqual(parsed.action, action)
                self.assertEqual(parsed.scope, self.scope)
                self.assertEqual(parsed.body, raw)
                self.assertEqual(parsed.body_sha256, sha(raw))
                for key, value in {**defaults, **extra}.items():
                    self.assertEqual(getattr(parsed, key), value, key)
                unpadded = self.request(action)
                self.assertNotEqual(parsed.body_sha256, unpadded.body_sha256)

    def test_five_acknowledgments_bind_original_request_identity_and_exact_values(self):
        defaults = {"available_digests": (), "unavailable_digests": (), "layer_sizes": (),
            "layer_media_types": (), "upload_id": None,
            "part_size": None, "last_byte_received": None, "layer_digest": None,
            "image_digest": None, "image_tag": None, "image_manifest_media_type": None}
        expected = (
            {"available_digests": (DIGEST,), "unavailable_digests": (OTHER_DIGEST,),
             "layer_sizes": ((DIGEST, len(PART)),),
             "layer_media_types": ((DIGEST, "application/vnd.oci.image.layer.v1.tar"),)},
            {"upload_id": UPLOAD, "part_size": 5 * 1024**2},
            {"upload_id": UPLOAD, "last_byte_received": 7 + len(PART) - 1},
            {"upload_id": UPLOAD, "layer_digest": DIGEST},
            {"image_digest": MANIFEST_DIGEST, "image_tag": TAG, "image_manifest_media_type": MEDIA},
        )
        for action, extra in zip(ACTIONS, expected):
            with self.subTest(action=action):
                request = self.request(action)
                result = self.response(request)
                self.assertIs(result.request, request)
                self.assertEqual(result.request_sha256, sha(request.body))
                self.assertEqual(result.action, action)
                for key, value in {**defaults, **extra}.items():
                    self.assertEqual(getattr(result, key), value, key)

    def test_closed_scope_grammar_explicit_account_repository_and_action(self):
        good = {"registry_id": REGISTRY, "region": REGION, "repository_name": REPOSITORY}
        for field, value in (("registry_id", 123456789012), ("registry_id", "１" * 12),
                ("registry_id", "0" * 11), ("registry_id", REGISTRY + "\n"),
                ("region", "cn-north-1"), ("region", "us-gov-west-1"),
                ("region", "US-east-1"), ("region", "us-east-0"),
                ("region", "us-east-100"), ("region", "us-" + "a" * 59 + "-1"),
                ("repository_name", "a"), ("repository_name", "a" * 257),
                ("repository_name", "Upper"), ("repository_name", "a//b"),
                ("repository_name", "a..b"), ("repository_name", "/repo"),
                ("repository_name", "team/repo___cache"),
                ("repository_name", "repo/"), ("repository_name", "repo:tag"),
                ("repository_name", "repo\n"), ("repository_name", True)):
            with self.subTest(field=field, value=value):
                self.refused(protocol.Scope, **{**good, field: value})
        for region, repository in (("us-west-1", "a_b/c.d-e"), ("zz-example-99", "a" * 256),
                (REGION, "team/repo__cache"), (REGION, "team/repo--cache")):
            scope = protocol.Scope(registry_id="0" * 12, region=region, repository_name=repository)
            self.assertEqual(scope.repository_name, repository)  # Shape only, no real-account claim.
        for action in ACTIONS:
            for field, value in (("registryId", "000000000000"), ("repositoryName", "other/repo")):
                self.refused(self.request, action, {**request_value(action), field: value})
        for action in ("GetAuthorizationToken", "PutImage ", "putimage", "", True, None):
            self.refused(protocol.parse_request, scope=self.scope, action=action,
                         body=encoded(request_value("InitiateLayerUpload")))
        for scope in (None, {}, object()):
            self.refused(protocol.parse_request, scope=scope, action=ACTIONS[1],
                         body=encoded(request_value(ACTIONS[1])))

    def test_strict_json_types_duplicates_nonfinite_depth_and_closed_fields(self):
        raw = encoded(request_value("InitiateLayerUpload"))
        duplicate = b'{"registryId":"' + REGISTRY.encode() + b'",' + raw[1:]
        invalid = [b"", b"\xff", b"\xef\xbb\xbf" + raw, raw + b"{}", b"[]", b"null", b"true",
            duplicate, b"[" * 1000 + b"0" + b"]" * 1000, raw.decode(), bytearray(raw), memoryview(raw)]
        for body in invalid:
            self.refused(self.request, "InitiateLayerUpload", raw=body)
        for action in ACTIONS:
            body = request_value(action)
            required = set(body) - ({"imageManifestMediaType", "imageDigest"} if action == "PutImage" else set())
            for missing in required:
                wrong = deepcopy(body)
                del wrong[missing]
                self.refused(self.request, action, wrong)
            self.refused(self.request, action, {**body, "unexpected": "PRIVATE-CANARY"})
        for number in (b"NaN", b"Infinity", b"-Infinity", b"7.0", b"7e0", b"true", b"false"):
            body = encoded(request_value("UploadLayerPart")).replace(b'"partFirstByte": 7', b'"partFirstByte": ' + number)
            self.refused(self.request, "UploadLayerPart", raw=body)

    def test_digest_arrays_count_uniqueness_and_complete_singleton(self):
        for action in ("BatchCheckLayerAvailability", "CompleteLayerUpload"):
            for values in ([], [DIGEST, DIGEST], [True], [None], DIGEST,
                    ["sha256:" + "A" * 64], [DIGEST + "\n"], ["sha512:" + "a" * 64],
                    ["sha256:" + "a" * 63]):
                self.refused(self.request, action, {**request_value(action), "layerDigests": values})
        many = ["sha256:" + f"{index:064x}" for index in range(100)]
        result = self.request("BatchCheckLayerAvailability", {**request_value(ACTIONS[0]), "layerDigests": many})
        self.assertEqual(result.layer_digests, tuple(many))
        self.refused(self.request, ACTIONS[0], {**request_value(ACTIONS[0]), "layerDigests": many + ["sha256:" + "f" * 64]})
        self.refused(self.request, "CompleteLayerUpload", {**request_value(ACTIONS[3]), "layerDigests": [DIGEST, OTHER_DIGEST]})

    def test_part_canonical_base64_offsets_uuid_and_integer_bounds(self):
        body = request_value("UploadLayerPart")
        # Offsets match the bytes a permissive decoder would produce, so these
        # negatives actually protect the canonical alphabet/padding contract.
        for text, last in (("", 0), ("TWE", 1), ("TWF=", 1), ("_w==", 0),
                           ("YQ==\n", 0), ("YQ====", 0), ("λ", 0), ([], 0)):
            self.refused(self.request, "UploadLayerPart", {**body, "partFirstByte": 0,
                "partLastByte": last, "layerPartBlob": text})
        for key, wrong in (("partFirstByte", -1), ("partLastByte", 0),
                ("partLastByte", body["partLastByte"] + 1), ("partLastByte", 2**63),
                ("partFirstByte", "7"), ("partLastByte", True),
                ("uploadId", UPLOAD + "\n"), ("uploadId", UPLOAD.replace("-", "")),
                ("uploadId", "not-a-uuid")):
            self.refused(self.request, "UploadLayerPart", {**body, key: wrong})
        for first in (0, 2**63 - 1):
            parsed = self.request("UploadLayerPart", {**body, "partFirstByte": first,
                "partLastByte": first, "layerPartBlob": "/w==", "uploadId": "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"})
            self.assertEqual(parsed.part_bytes, b"\xff")
            self.assertEqual(parsed.part_last_byte, first)

    def test_put_optional_media_digest_tag_and_original_manifest_bytes(self):
        base = request_value("PutImage")
        for media in (MEDIA, DOCKER_MEDIA):
            result = self.request("PutImage", {**base, "imageManifestMediaType": media})
            self.assertEqual(result.image_manifest_media_type, media)
        minimal = {key: value for key, value in base.items() if key not in {"imageDigest", "imageManifestMediaType"}}
        request = self.request("PutImage", minimal)
        self.assertIsNone(request.image_digest)
        self.assertIsNone(request.image_manifest_media_type)
        self.assertEqual(self.response(request).image_digest, MANIFEST_DIGEST)
        for key, wrong in (("imageTag", ""), ("imageTag", "a" * 301), ("imageTag", "has space"),
                ("imageTag", "tag\n"), ("imageManifest", ""), ("imageManifest", None),
                ("imageManifest", "\ud800"), ("imageManifestMediaType", "application/json"),
                ("imageManifestMediaType", None), ("imageDigest", OTHER_DIGEST), ("imageDigest", None)):
            value = {**base, key: wrong}
            # JSON escaped surrogate stays encodable but is not valid scalar UTF8.
            self.refused(self.request, "PutImage", raw=json.dumps(value).encode())
        result = self.request("PutImage", {**minimal, "imageTag": "!" * 300,
                                         "imageManifest": "opaque λ: not artifact validation"})
        self.assertEqual(result.image_manifest, "opaque λ: not artifact validation".encode())

    def test_real_request_part_and_manifest_size_boundaries(self):
        # Real bounded allocations, never altered production limits or a fake len.
        raw = encoded(request_value("InitiateLayerUpload"))
        wire = raw + b" " * (16 * 1024**2 - len(raw))
        self.assertEqual(self.request("InitiateLayerUpload", raw=wire).body, wire)
        self.refused(self.request, "InitiateLayerUpload", raw=wire + b" ")
        del wire
        part = b"x" * (10 * 1024**2)
        body = {**request_value("UploadLayerPart"), "partFirstByte": 0,
                "partLastByte": len(part) - 1, "layerPartBlob": base64.b64encode(part).decode()}
        self.assertEqual(self.request("UploadLayerPart", body).part_bytes, part)
        body.update(partLastByte=len(part), layerPartBlob=base64.b64encode(part + b"x").decode())
        self.refused(self.request, "UploadLayerPart", body)
        del body, part
        body = {**request_value("PutImage"), "imageManifest": "x" * (4 * 1024**2)}
        del body["imageDigest"]
        self.assertEqual(len(self.request("PutImage", body).image_manifest), 4 * 1024**2)
        body["imageManifest"] += "x"
        self.refused(self.request, "PutImage", body)

    def test_raw_response_status_json_exact_keys_and_real_size_cap(self):
        request = self.request("InitiateLayerUpload")
        for status in (True, 200.0, "200", 201, 204, 301, 400, 409, 500):
            self.refused(self.response, request, status=status)
        raw = encoded(response_value(request.action))
        for body in (b"", b"\xff", b"[]", b"null", b"{}", raw + b"{}",
                raw.decode(), bytearray(raw), b'{"uploadId":"' + UPLOAD.encode() + b'",' + raw[1:]):
            self.refused(self.response, request, raw=body)
        for action in ACTIONS:
            request = self.request(action)
            self.refused(self.response, request, {**response_value(action), "ResponseMetadata": {"HTTPStatusCode": 200}})
            for other in ACTIONS:
                if other != action:
                    self.refused(self.response, request, response_value(other))
        request = self.request("InitiateLayerUpload")
        wire = raw + b" " * (25 * 1024**2 - len(raw))
        self.assertEqual(self.response(request, raw=wire).upload_id, UPLOAD)
        self.refused(self.response, request, raw=wire + b" ")

    def test_batch_response_complete_unique_cover_and_no_failures(self):
        request = self.request(ACTIONS[0])
        base = response_value(ACTIONS[0])
        without = deepcopy(base)
        del without["failures"]
        self.assertEqual(self.response(request, without).available_digests, (DIGEST,))
        reordered = deepcopy(base)
        reordered["layers"][1].update(layerSize=0, mediaType="application/octet-stream")
        reordered["layers"].reverse()
        result = self.response(request, reordered)
        self.assertEqual(result.layer_sizes, ((DIGEST, len(PART)), (OTHER_DIGEST, 0)))
        self.assertEqual(result.layer_media_types, (
            (DIGEST, "application/vnd.oci.image.layer.v1.tar"),
            (OTHER_DIGEST, "application/octet-stream")))
        self.assertEqual(result.available_digests, (DIGEST,))
        self.assertEqual(result.unavailable_digests, (OTHER_DIGEST,))
        invalid = [{**base, "layers": []}, {**base, "layers": base["layers"][:1]},
            {**base, "layers": [base["layers"][0]] * 2},
            {**base, "failures": [{"layerDigest": OTHER_DIGEST, "failureCode": "MissingLayerDigest"}]},
            {**base, "failures": None}]
        for field, wrong in (("layerDigest", "sha256:" + "0" * 64), ("layerAvailability", "UNKNOWN"),
                ("layerAvailability", True), ("layerSize", -1), ("layerSize", True),
                ("layerSize", 1.0), ("layerSize", 2**63), ("mediaType", "text/plain; charset=utf-8"),
                ("mediaType", "bad media"), ("extra", "PRIVATE-CANARY")):
            row = deepcopy(base)
            row["layers"][0][field] = wrong
            invalid.append(row)
        for value in invalid:
            self.refused(self.response, request, value)
        for missing in ("layerDigest", "layerAvailability"):
            value = deepcopy(base)
            del value["layers"][0][missing]
            self.refused(self.response, request, value)

    def test_initiate_upload_and_complete_acknowledgment_joins(self):
        for action, changes in (
            ("InitiateLayerUpload", ({"partSize": 0}, {"partSize": True}, {"partSize": 1.0},
                {"partSize": 10 * 1024**2 + 1}, {"uploadId": "invalid"}, {"registryId": REGISTRY})),
            ("UploadLayerPart", ({"registryId": "000000000000"}, {"repositoryName": "other"},
                {"uploadId": OTHER_UPLOAD}, {"lastByteReceived": 0}, {"lastByteReceived": True},
                {"lastByteReceived": 7 + len(PART)})),
            ("CompleteLayerUpload", ({"registryId": "000000000000"}, {"repositoryName": "other"},
                {"uploadId": OTHER_UPLOAD}, {"layerDigest": OTHER_DIGEST}, {"layerDigest": DIGEST.upper()}))):
            request = self.request(action)
            base = response_value(action)
            for changed in changes:
                self.refused(self.response, request, {**base, **changed})
            for missing in base:
                self.refused(self.response, request, {key: value for key, value in base.items() if key != missing})
        self.assertEqual(self.response(self.request("InitiateLayerUpload"),
            {"uploadId": UPLOAD, "partSize": 10 * 1024**2}).part_size, 10 * 1024**2)

    def test_put_response_exact_manifest_digest_tag_scope_and_media(self):
        request = self.request("PutImage")
        base = response_value("PutImage")
        for field, wrong in (("registryId", "000000000000"), ("repositoryName", "other"),
                ("imageManifest", MANIFEST + " "), ("imageManifestMediaType", DOCKER_MEDIA),
                ("imageManifestMediaType", None), ("extra", "PRIVATE-CANARY")):
            changed = deepcopy(base)
            changed["image"][field] = wrong
            self.refused(self.response, request, changed)
        for field, wrong in (("imageDigest", OTHER_DIGEST), ("imageTag", "other"), ("extra", "x")):
            changed = deepcopy(base)
            changed["image"]["imageId"][field] = wrong
            self.refused(self.response, request, changed)
        for missing in ("imageDigest", "imageTag"):
            changed = deepcopy(base)
            del changed["image"]["imageId"][missing]
            self.refused(self.response, request, changed)
        for missing in base["image"]:
            changed = deepcopy(base)
            del changed["image"][missing]
            self.refused(self.response, request, changed)
        minimal = request_value("PutImage")
        del minimal["imageManifestMediaType"]
        request = self.request("PutImage", minimal)
        del base["image"]["imageManifestMediaType"]
        result = self.response(request, base)
        self.assertEqual(result.image_digest, MANIFEST_DIGEST)
        self.assertIsNone(result.image_manifest_media_type)

    def test_sealed_frozen_redacted_results_request_binding_and_network_denial(self):
        for action in ACTIONS:
            request = self.request(action)
            response = self.response(request)
            self.assertIsNone(protocol.require_request(request))
            self.assertIsNone(protocol.require_response(response))
            for value in (request, response):
                self.assertNotIn("CANARY", repr(value))
                self.assertNotIn("layerPartBlob", repr(value))
                with self.assertRaises(FrozenInstanceError):
                    value.action = "different"
                self.refused(type(value))
        forged = object.__new__(protocol.Request)
        self.refused(protocol.parse_response, forged, status=200, body=encoded(response_value(ACTIONS[1])))
        for value in (None, {}, object(), forged, object.__new__(protocol.Response)):
            self.refused(protocol.require_request, value)
            self.refused(protocol.require_response, value)
        self.refused(protocol.require_request, response)
        self.refused(protocol.require_response, request)
        first = self.request("UploadLayerPart")
        changed = request_value("UploadLayerPart")
        changed.update(partFirstByte=8, partLastByte=8 + len(PART) - 1)
        second = self.request("UploadLayerPart", changed)
        self.assertNotEqual(first.body_sha256, second.body_sha256)
        self.refused(self.response, second, response_value("UploadLayerPart"))
        ack = self.response(first)
        self.assertIs(ack.request, first)
        self.assertIsNot(ack.request, second)
        with self.assertRaises(PermissionError):
            socket.socket()
        with self.assertRaises(PermissionError):
            socket.getaddrinfo("never-resolved.invalid", 443)


if __name__ == "__main__":
    unittest.main(verbosity=2)
