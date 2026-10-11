#!/usr/bin/env python3
"""Offline stock Boto3 publication simulation, not AWS/proxy/authority acceptance.

Run with /usr/bin/python3 -B scripts/test_ecr_sdk_publication.py -f.
The real pinned SDK serializes every operation and parses synthetic AWSResponse
objects. Only its HTTP send boundary is intercepted. Actual sealed content,
protocol parsing, publication transitions and signing are exercised locally;
there is no approval, durable ledger, native hardware, socket or AWS operation.
"""
from contextlib import ExitStack
from copy import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

if sys.flags.optimize:
    raise RuntimeError("ECR SDK publication tests require enabled assertions")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
NETWORK = []


def prohibit_network(event, args):
    if event.startswith("socket."):
        NETWORK.append(event)
        raise PermissionError("offline ECR publication forbids sockets and DNS")


# Before SDK import, including urllib3's optional IPv6 feature probe.
sys.addaudithook(prohibit_network)

from serverware import aws_ecr_signing as signing
from serverware import ecr_image_artifact as artifact
from serverware import ecr_image_custody as custody
from serverware import ecr_publication_plan as planner
from serverware import ecr_sdk_protocol as protocol

REGION, REGISTRY, REPOSITORY = "us-east-1", "123456789012", "serverware-fixture"
ENDPOINT = "https://api.ecr.us-east-1.amazonaws.com/"
TARGET_PREFIX = "AmazonEC2ContainerRegistry_V20150921."
# Public inert examples, not AWS credentials. Provider-side tuple is deliberately
# different from the SDK dummy, including its optional synthetic session token.
CLIENT_ACCESS = "AKIAIOSFODNN7EXAMPLE"
CLIENT_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
SERVER_ACCESS = "AKIA" + "S" * 16
SERVER_SESSION_ACCESS = "ASIA" + "T" * 16
SERVER_SECRET = "A" * 40
SERVER_TOKEN = "public-synthetic-server-session"
NOW = int(datetime(2026, 10, 10, 12, tzinfo=timezone.utc).timestamp())
MONO = 1_000_000_000_000
PART_SIZE = 8  # Tiny synthetic provider ACK, not a real ECR sizing claim.
TAG = "offline-fixture"
MEDIA = artifact.OCI_MANIFEST
ACTIONS = ("BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload", "PutImage")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def image_fixture():
    vector = json.loads((ROOT / "scripts/fixtures/ecr_image_artifact_v1.json").read_text())
    original = vector["manifest"].encode("utf-8")
    blobs = {row["digest"]: row["utf8"].encode("utf-8") for row in vector["blobs"]}
    # Verify the literal cross-language vector before extending the tiny image.
    verified = artifact.verify_image(original, {name: io.BytesIO(raw) for name, raw in blobs.items()})
    assert verified.commitment() == vector["expected_commitment"]
    assert verified.commitment_sha256 == vector["expected_commitment_sha256"]
    manifest = json.loads(original)
    second = b"synthetic-layer\nsecond-content\x00\xff"
    second_digest = sha(second)
    manifest["layers"].insert(1, {"mediaType": "application/vnd.oci.image.layer.v1.tar",
        "digest": second_digest, "size": len(second)})
    blobs[second_digest] = second
    raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    # Publish in non-manifest order, including a common-prefix ambiguous layer.
    order = [second_digest, manifest["config"]["digest"], manifest["layers"][0]["digest"]]
    return raw, blobs, order


class RawResponse:
    def __init__(self, body):
        self.body = body

    def stream(self, amt=None, decode_content=False):
        yield self.body


class InterceptRefusal(BaseException):
    """Stop at a failed local contract; never let SDK retry a local refusal."""


class OfflinePublication:
    """Independent synthetic receiver and actual component joins, no sockets."""
    def __init__(self, test, *, session=False, fault=None):
        self.test, self.fault = test, fault
        self.stack = ExitStack()
        test.addCleanup(self.stack.close)
        environment = {key: value for key, value in os.environ.items()
            if not key.startswith(("AWS_", "BOTO_"))
            and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
        environment.update(AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
            BOTO_CONFIG="/dev/null", AWS_EC2_METADATA_DISABLED="true")
        self.stack.enter_context(patch.dict(os.environ, environment, clear=True))
        import boto3
        import botocore
        import botocore.auth
        import botocore.credentials
        import botocore.session
        from botocore.config import Config
        for module in (boto3, botocore):
            test.assertEqual(module.__version__, "1.34.46")
            test.assertEqual(Path(module.__file__).resolve(), Path("/usr/lib/python3/dist-packages") / module.__name__ / "__init__.py")
        for owner, name in ((botocore.session.Session, "get_credentials"),
                (botocore.credentials, "create_credential_resolver"),
                (botocore.credentials.CredentialResolver, "load_credentials")):
            self.stack.enter_context(patch.object(owner, name,
                side_effect=AssertionError("ambient credential lookup forbidden")))
        self.stack.enter_context(patch.object(botocore.auth.logger, "disabled", True))
        fake = {"aws_access_key_id": CLIENT_ACCESS, "aws_secret_access_key": CLIENT_SECRET, "aws_session_token": None}
        self.client = boto3.Session(region_name=REGION, **fake).client("ecr", endpoint_url=ENDPOINT,
            region_name=REGION, verify=True, **fake, config=Config(signature_version="v4",
                retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, connect_timeout=1, read_timeout=1,
                defaults_mode="legacy", ignore_configured_endpoint_urls=True,
                use_dualstack_endpoint=False, use_fips_endpoint=False))
        self.stack.callback(self.client.close)
        test.assertIs(self.client._endpoint.http_session._verify, True)
        test.assertEqual(self.client.meta.config.retries["total_max_attempts"], 1)
        self.client.meta.events.register("before-sign.ecr", self.before_sign)
        self.stack.enter_context(patch.object(self.client._endpoint.http_session, "send", side_effect=self.send))
        self.manifest, self.blobs, self.order = image_fixture()
        self.sources = {name: io.BytesIO(raw) for name, raw in self.blobs.items()}
        self.custody = self.stack.enter_context(custody.capture(self.manifest, self.sources))
        test.assertIs(type(self.custody.image), artifact.VerifiedImage)
        test.assertEqual(self.custody.image.manifest_bytes, self.manifest)
        test.assertEqual(len(self.custody.image.layers), 3)
        test.assertEqual(len(self.custody.image.blobs), 3)
        test.assertEqual(self.custody.image.layers[0], self.custody.image.layers[2])
        self.scope = protocol.Scope(REGISTRY, REGION, REPOSITORY)
        self.publication_scope = planner.PublicationScope(protocol_scope=self.scope,
            publication_id="synthetic-publication", principal_id="synthetic-app", route_id="synthetic-route",
            credential_id="synthetic-credential", credential_generation=7, policy_hash="sha256:" + "1" * 64,
            image_tag=TAG)
        self.snapshot = planner.create(self.custody.image, self.publication_scope,
            clock=planner.Clock(NOW, MONO), deadline=planner.Deadline(NOW + 120, MONO + 120_000_000_000))
        self.server_credentials = signing.Credentials(kind="session" if session else "long_term",
            access_key_id=SERVER_SESSION_ACCESS if session else SERVER_ACCESS,
            secret_access_key=SERVER_SECRET, session_token=SERVER_TOKEN if session else None,
            expires_at="2026-10-10T12:10:00Z" if session else None)
        self.calls, self.signed, self.parsed = [], [], []
        self.uploads, self.completed = {}, set()
        self.sdk_request = None
        self.sends_this_call = 0
        self.final_manifest = None
        self.initial_network_attempts = len(NETWORK)

    def before_sign(self, request, **kwargs):
        # This object was constructed by Botocore from its real service model.
        # Copy it, rather than inventing an AWSRequest for serialization/signing.
        self.sdk_request = copy(request)
        self.sdk_request.context = dict(request.context)
        self.sdk_request.headers = copy(request.headers)

    def clock(self):
        return planner.Clock(NOW + len(self.calls), MONO + len(self.calls) * 1_000_000_000)

    def call(self, action, **fields):
        self.sends_this_call = 0
        self.sdk_request = None
        methods = [name for name, operation in self.client.meta.method_to_api_mapping.items()
            if operation == action]
        self.test.assertEqual(len(methods), 1)
        result = getattr(self.client, methods[0])(
            registryId=fields.pop("registryId", REGISTRY), repositoryName=REPOSITORY, **fields)
        self.test.assertEqual(self.sends_this_call, 1)
        self.test.assertEqual(result["ResponseMetadata"]["HTTPStatusCode"], 200)
        self.test.assertEqual(result["ResponseMetadata"]["RetryAttempts"], 0)
        self.parsed.append(action)
        return result

    def verify_signature(self, signed, body):
        from botocore.auth import SigV4Auth
        from botocore.compat import HTTPHeaders
        from botocore.credentials import Credentials
        request = copy(self.sdk_request)
        self.test.assertIsNotNone(request)
        self.test.assertEqual(request.body, body)
        request.context = dict(request.context)
        request.headers = HTTPHeaders()
        final = dict(signed.headers)
        for name, value in signed.headers:
            if name != "authorization":
                request.headers[name] = value
        request.context["timestamp"] = final["x-amz-date"]
        material = self.server_credentials
        oracle = SigV4Auth(Credentials(material.access_key_id, material.secret_access_key, material.session_token), "ecr", REGION)
        canonical = oracle.canonical_request(request)
        to_sign = oracle.string_to_sign(request, canonical)
        expected = "AWS4-HMAC-SHA256 Credential=" + oracle.scope(request) + ", SignedHeaders=" + \
            oracle.signed_headers(oracle.headers_to_sign(request)) + ", Signature=" + oracle.signature(to_sign, request)
        self.test.assertEqual(final["authorization"], expected)
        self.test.assertEqual(signed.canonical_request, canonical.encode("utf-8"))
        self.test.assertEqual(signed.string_to_sign, to_sign)
        self.test.assertNotIn(CLIENT_ACCESS, final["authorization"])
        self.test.assertEqual(final.get("x-amz-security-token"), material.session_token)

    def response(self, request):
        common = {"registryId": REGISTRY, "repositoryName": REPOSITORY}
        if request.action == "BatchCheckLayerAvailability":
            return {"layers": [{"layerDigest": value, "layerAvailability": "UNAVAILABLE"} for value in request.layer_digests], "failures": []}
        if request.action == "InitiateLayerUpload":
            upload = "00000000-0000-4000-8000-" + str(len(self.uploads) + 1).zfill(12)
            self.uploads[upload] = bytearray()
            return {"uploadId": upload, "partSize": PART_SIZE}
        raw = self.uploads.get(request.upload_id)
        if request.action == "UploadLayerPart":
            self.test.assertIsNotNone(raw)
            self.test.assertEqual(request.part_first_byte, len(raw))
            self.test.assertEqual(request.part_last_byte, len(raw) + len(request.part_bytes) - 1)
            raw.extend(request.part_bytes)
            return {**common, "uploadId": request.upload_id, "lastByteReceived": len(raw) - 1}
        if request.action == "CompleteLayerUpload":
            self.test.assertIsNotNone(raw)
            selected = request.layer_digests[0]
            self.test.assertEqual(sha(raw), selected)
            self.test.assertEqual(bytes(raw), self.blobs[selected])
            self.completed.add(selected)
            return {**common, "uploadId": request.upload_id, "layerDigest": selected}
        self.test.assertEqual(request.action, "PutImage")
        self.test.assertEqual(self.completed, set(self.blobs))
        self.test.assertEqual(request.image_manifest, self.manifest)
        self.test.assertEqual(request.image_digest, sha(self.manifest))
        self.test.assertEqual(request.image_tag, TAG)
        self.final_manifest = request.image_manifest
        return {"image": {**common, "imageId": {"imageDigest": sha(self.manifest), "imageTag": TAG},
            "imageManifest": self.manifest.decode("utf-8"), "imageManifestMediaType": MEDIA}}

    def send(self, prepared):
        from botocore.awsrequest import AWSResponse
        self.sends_this_call += 1
        self.test.assertEqual(self.sends_this_call, 1, "SDK retried an intercepted operation")
        self.test.assertLess(len(self.calls), 40)
        self.test.assertEqual((prepared.method, prepared.url), ("POST", ENDPOINT))
        self.test.assertIs(type(prepared.body), bytes)
        self.test.assertIsNotNone(self.sdk_request)
        self.test.assertEqual(self.sdk_request.body, prepared.body)
        headers = {name.lower(): value.decode("ascii") if isinstance(value, bytes) else value
            for name, value in prepared.headers.items()}
        self.test.assertEqual(headers["content-type"], "application/x-amz-json-1.1")
        self.test.assertEqual(headers["content-length"], str(len(prepared.body)))
        self.test.assertEqual(headers.get("host", "api.ecr.us-east-1.amazonaws.com"), "api.ecr.us-east-1.amazonaws.com")
        self.test.assertTrue(headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=" + CLIENT_ACCESS + "/"))
        self.test.assertNotIn("x-amz-security-token", headers)
        target = headers["x-amz-target"]
        self.test.assertTrue(target.startswith(TARGET_PREFIX))
        action = target[len(TARGET_PREFIX):]
        self.calls.append(action)
        try:
            request = protocol.parse_request(scope=self.scope, action=action, body=prepared.body)
            pending, plan = planner.begin(self.snapshot, request, clock=self.clock(), read_blob=self.custody.read_blob)
        except ValueError:
            raise InterceptRefusal("local request refused before signing") from None
        self.snapshot = pending
        clock = self.clock()
        signed = signing.sign(self.server_credentials, region=REGION, action=action, body=request.body,
            clock=signing.ClockObservation(clock.unix_seconds, clock.monotonic_ns))
        signing.assert_dispatch(signed, method=prepared.method, scheme="https", authority="api.ecr.us-east-1.amazonaws.com",
            path="/", query="", headers=signed.headers, body=prepared.body,
            clock=signing.ClockObservation(clock.unix_seconds, clock.monotonic_ns))
        self.verify_signature(signed, prepared.body)
        self.signed.append(action)
        result = self.response(request)
        status = 200
        if self.fault == "wrong-upload-id" and action == "UploadLayerPart":
            result["uploadId"] = "00000000-0000-4000-8000-999999999999"
        if self.fault == "wrong-image-digest" and action == "PutImage":
            result["image"]["imageId"]["imageDigest"] = "sha256:" + "f" * 64
        if self.fault == "server-error" and action == "InitiateLayerUpload":
            status, result = 500, {"__type": "ServerException", "message": "Synthetic provider failure"}
        raw = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            response = protocol.parse_response(request, status=status, body=raw)
            self.snapshot = planner.apply_response(pending, plan, response, clock=self.clock())
        except ValueError:
            self.snapshot = planner.fail(pending, plan, clock=self.clock())
            if status == 200:
                raise InterceptRefusal("local response refused; no success ACK") from None
        return AWSResponse(ENDPOINT, status, {"Content-Type": "application/x-amz-json-1.1",
            "Content-Length": str(len(raw)), "x-amzn-RequestId": "synthetic-offline-request"}, RawResponse(raw))

    def upload_all(self):
        self.call("BatchCheckLayerAvailability", layerDigests=sorted(self.blobs))
        for selected in self.order:
            self.upload_blob(selected)

    def upload_blob(self, selected, upload=None):
        if upload is None:
            response = self.call("InitiateLayerUpload")
            self.test.assertEqual(response["partSize"], PART_SIZE)
            upload = response["uploadId"]
        body = self.blobs[selected]
        for offset in range(0, len(body), PART_SIZE):
            part = body[offset:offset + PART_SIZE]
            acknowledged = self.call("UploadLayerPart", uploadId=upload,
                partFirstByte=offset, partLastByte=offset + len(part) - 1, layerPartBlob=part)
            self.test.assertEqual(acknowledged["lastByteReceived"], offset + len(part) - 1)
        self.test.assertEqual(self.call("CompleteLayerUpload", uploadId=upload,
            layerDigests=[selected])["layerDigest"], selected)

    def put(self):
        return self.call("PutImage", imageManifest=self.manifest.decode("utf-8"),
            imageManifestMediaType=MEDIA, imageTag=TAG, imageDigest=sha(self.manifest))


class EcrSdkPublicationTests(unittest.TestCase):
    def test_complete_stock_sdk_publication_with_both_server_tuple_kinds(self):
        for session in (False, True):
            with self.subTest(session=session):
                flow = OfflinePublication(self, session=session)
                flow.upload_all()
                result = flow.put()
                self.assertEqual(result["image"]["imageId"], {"imageDigest": sha(flow.manifest), "imageTag": TAG})
                self.assertEqual(result["image"]["imageManifest"].encode("utf-8"), flow.manifest)
                self.assertEqual(flow.snapshot.status, "published")
                self.assertEqual(set(flow.calls), set(ACTIONS))
                self.assertEqual(flow.calls, flow.signed)
                self.assertEqual(flow.calls, flow.parsed)
                self.assertEqual(flow.final_manifest, flow.custody.image.manifest_bytes)
                self.assertEqual(flow.completed, set(flow.blobs))
                self.assertEqual(len(flow.uploads), 3)
                self.assertEqual(len(NETWORK), flow.initial_network_attempts)
                flow.stack.close()

    def test_mutable_originals_cannot_replace_sealed_publication_bytes(self):
        flow = OfflinePublication(self)
        for digest, source in flow.sources.items():
            self.assertFalse(source.closed)
            source.seek(0)
            source.write(b"X" * len(flow.blobs[digest]))
            self.assertNotEqual(source.getvalue(), flow.blobs[digest])
        selected = flow.order[0]
        flow.call("BatchCheckLayerAvailability", layerDigests=sorted(flow.blobs))
        upload = flow.call("InitiateLayerUpload")["uploadId"]
        count = len(flow.signed)
        with self.assertRaises(InterceptRefusal):
            flow.call("UploadLayerPart", uploadId=upload, partFirstByte=0, partLastByte=7,
                layerPartBlob=flow.sources[selected].getvalue()[:8])
        self.assertEqual(len(flow.signed), count)
        self.assertEqual(flow.uploads[upload], b"")
        # Continue only after a pre-sign refusal: no provider effect occurred.
        # Every successful part is still compared against real sealed memfds.
        flow.upload_blob(selected, upload)
        for digest in flow.order[1:]:
            flow.upload_blob(digest)
        flow.put()
        self.assertEqual(flow.snapshot.status, "published")
        self.assertEqual(flow.final_manifest, flow.manifest)
        self.assertEqual(flow.completed, set(flow.blobs))
        self.assertEqual(len(NETWORK), flow.initial_network_attempts)

    def test_wrong_scope_and_out_of_bundle_sdk_operations_never_sign(self):
        for action, fields in (("BatchCheckLayerAvailability", {"registryId": "999999999999", "layerDigests": ["sha256:" + "1" * 64]}),
                ("DeleteRepository", {"force": True})):
            with self.subTest(action=action):
                flow = OfflinePublication(self)
                with self.assertRaises(InterceptRefusal):
                    flow.call(action, **fields)
                self.assertEqual(flow.sends_this_call, 1)
                self.assertEqual(flow.signed, [])
                self.assertEqual(flow.snapshot.status, "fresh")
                flow.stack.close()

    def test_wrong_content_and_premature_manifest_never_sign(self):
        flow = OfflinePublication(self)
        with self.assertRaises(InterceptRefusal):
            flow.put()
        self.assertEqual(flow.signed, [])
        flow.call("BatchCheckLayerAvailability", layerDigests=sorted(flow.blobs))
        upload = flow.call("InitiateLayerUpload")["uploadId"]
        count = len(flow.signed)
        with self.assertRaises(InterceptRefusal):
            flow.call("UploadLayerPart", uploadId=upload, partFirstByte=0, partLastByte=7, layerPartBlob=b"WRONG!!!")
        self.assertEqual(len(flow.signed), count)
        self.assertEqual(flow.uploads[upload], b"")
        self.assertIsNone(flow.final_manifest)

    def test_mismatched_provider_acknowledgements_never_publish_or_retry(self):
        for fault in ("wrong-upload-id", "wrong-image-digest"):
            with self.subTest(fault=fault):
                flow = OfflinePublication(self, fault=fault)
                with self.assertRaises(InterceptRefusal):
                    flow.upload_all()
                    flow.put()
                self.assertEqual(flow.sends_this_call, 1)
                self.assertIn(flow.snapshot.status, {"uncertain", "failed"})
                self.assertNotEqual(flow.snapshot.status, "published")
                flow.stack.close()

    def test_real_sdk_error_parser_has_one_attempt_and_no_success_transition(self):
        from botocore.exceptions import ClientError
        flow = OfflinePublication(self, fault="server-error")
        flow.call("BatchCheckLayerAvailability", layerDigests=sorted(flow.blobs))
        with self.assertRaises(ClientError) as caught:
            flow.call("InitiateLayerUpload")
        self.assertEqual(caught.exception.response["Error"]["Code"], "ServerException")
        self.assertEqual(caught.exception.response["ResponseMetadata"]["RetryAttempts"], 0)
        self.assertEqual(flow.calls.count("InitiateLayerUpload"), 1)
        self.assertEqual(flow.sends_this_call, 1)
        self.assertIn(flow.snapshot.status, {"uncertain", "failed"})

    def test_network_and_ambient_credentials_are_excluded(self):
        with self.assertRaises(PermissionError):
            socket.socket()
        original = dict(os.environ)
        flow = OfflinePublication(self)
        self.assertEqual(os.environ["AWS_SHARED_CREDENTIALS_FILE"], "/dev/null")
        self.assertEqual(os.environ["AWS_CONFIG_FILE"], "/dev/null")
        self.assertNotIn("AWS_PROFILE", os.environ)
        self.assertNotIn("AWS_ENDPOINT_URL", os.environ)
        self.assertEqual(flow.calls, [])
        flow.stack.close()
        self.assertEqual(dict(os.environ), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
