#!/usr/bin/env python3
"""Offline stock SDK serialization evidence, NOT proxy/AWS/job acceptance.

Only documented fake credentials and tiny synthetic inputs are used. The
unmodified, signed prepared request is captured at the HTTP send boundary;
no response is fabricated and no AWS operation succeeds. Run separately with
/usr/bin/python3 -B scripts/test_aws_ecr_sdk_contract.py.
"""
from contextlib import ExitStack, contextmanager
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

REGION, REGISTRY, REPOSITORY = "us-east-1", "123456789012", "catchplate-fixture"
ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
PART = b"synthetic-layer-part\x00\xff"
DIGEST = "sha256:" + hashlib.sha256(PART).hexdigest()
UPLOAD_ID = "00000000-0000-4000-8000-000000000001"
MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
MANIFEST = json.dumps({"schemaVersion": 2, "mediaType": MEDIA_TYPE,
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 2,
               "digest": "sha256:" + hashlib.sha256(b"{}").hexdigest()}, "layers": []},
    sort_keys=True, separators=(",", ":"))


def prohibit_network(event, args):
    if event.startswith("socket."):
        raise PermissionError("offline SDK contract forbids sockets and DNS")


# Installed before SDK imports, including urllib3's optional IPv6 socket probe.
# This intentionally process-wide guard is why the test is a separate script.
sys.addaudithook(prohibit_network)


@contextmanager
def isolated_aws_environment():
    environment = {key: value for key, value in os.environ.items()
        if not key.startswith(("AWS_", "BOTO_"))
        and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    environment.update(AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                       BOTO_CONFIG="/dev/null", AWS_EC2_METADATA_DISABLED="true")
    with patch.dict(os.environ, environment, clear=True):
        yield


class SendBoundaryReached(BaseException):
    """Fixed sentinel: stop before transport, without entering SDK retry logic."""


class AwsEcrSdkContractTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(isolated_aws_environment())
        import boto3
        import botocore
        import botocore.credentials
        import botocore.session
        from botocore.config import Config
        for module in (boto3, botocore):
            self.assertEqual(module.__version__, "1.34.46")
            self.assertEqual(Path(module.__file__).resolve(),
                             Path("/usr/lib/python3/dist-packages") / module.__name__ / "__init__.py")
        for owner, name in ((botocore.session.Session, "get_credentials"),
                (botocore.credentials, "create_credential_resolver"),
                (botocore.credentials.CredentialResolver, "load_credentials")):
            stack.enter_context(patch.object(owner, name,
                side_effect=AssertionError("ambient credential/provider lookup forbidden")))
        credentials = {"aws_access_key_id": ACCESS_KEY, "aws_secret_access_key": SECRET_KEY,
                       "aws_session_token": None}
        session = boto3.Session(region_name=REGION, **credentials)
        self.client = session.client("ecr", region_name=REGION, verify=True, **credentials,
            config=Config(signature_version="v4", retries={"mode": "standard", "total_max_attempts": 1},
                proxies={}, connect_timeout=1, read_timeout=1, defaults_mode="legacy",
                ignore_configured_endpoint_urls=True, use_dualstack_endpoint=False, use_fips_endpoint=False))
        stack.callback(self.client.close)
        self.assertIs(self.client._endpoint.http_session._verify, True)
        self.assertEqual(self.client.meta.config.retries["total_max_attempts"], 1)

    def request(self, method, target, **fields):
        captured, sentinel = [], SendBoundaryReached("offline prepared request captured")

        def capture(request):
            captured.append(request)
            raise sentinel

        inputs = {"registryId": REGISTRY, "repositoryName": REPOSITORY, **fields}
        with patch.object(self.client._endpoint.http_session, "send", side_effect=capture) as send:
            with self.assertRaises(SendBoundaryReached) as caught:
                getattr(self.client, method)(**inputs)
        self.assertIs(caught.exception, sentinel)
        send.assert_called_once()
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual((request.method, request.url), ("POST", "https://api.ecr.us-east-1.amazonaws.com/"))
        self.assertIs(type(request.body), bytes)
        self.assertLessEqual(len(request.body), 4096)
        headers = {name.lower(): value.decode("ascii") if isinstance(value, bytes) else value
                   for name, value in request.headers.items()}
        self.assertEqual(headers.get("host", "api.ecr.us-east-1.amazonaws.com"), "api.ecr.us-east-1.amazonaws.com")
        self.assertEqual(headers["content-type"], "application/x-amz-json-1.1")
        self.assertEqual(headers["x-amz-target"], "AmazonEC2ContainerRegistry_V20150921." + target)
        self.assertEqual(headers["content-length"], str(len(request.body)))
        self.assertNotIn("x-amz-security-token", headers)
        expected = dict(inputs)
        if "layerPartBlob" in expected:
            expected["layerPartBlob"] = base64.b64encode(expected["layerPartBlob"]).decode("ascii")
        self.assertEqual(json.loads(request.body), expected)
        self.verify_signature(headers, request.body)
        self.assertNotIn(SECRET_KEY, json.dumps(headers) + request.body.decode("ascii"))

    def verify_signature(self, headers, body):
        """Independently recompute the dummy-key SigV4 over captured bytes."""
        timestamp = headers["x-amz-date"]
        self.assertRegex(timestamp, r"^[0-9]{8}T[0-9]{6}Z$")
        scope = timestamp[:8] + "/" + REGION + "/ecr/aws4_request"
        signed = "content-type;host;x-amz-date;x-amz-target"
        prefix = "AWS4-HMAC-SHA256 Credential=" + ACCESS_KEY + "/" + scope + ", SignedHeaders=" + signed + ", Signature="
        authorization = headers["authorization"]
        self.assertTrue(authorization.startswith(prefix))
        signature = authorization[len(prefix):]
        self.assertRegex(signature, r"^[0-9a-f]{64}$")
        values = {"host": "api.ecr.us-east-1.amazonaws.com", **headers}
        canonical_headers = "".join(name + ":" + " ".join(values[name].split()) + "\n" for name in signed.split(";"))
        canonical = "\n".join(("POST", "/", "", canonical_headers, signed, hashlib.sha256(body).hexdigest()))
        string_to_sign = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, hashlib.sha256(canonical.encode()).hexdigest()))
        key = ("AWS4" + SECRET_KEY).encode()
        for value in (timestamp[:8], REGION, "ecr", "aws4_request"):
            key = hmac.new(key, value.encode(), hashlib.sha256).digest()
        self.assertEqual(signature, hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest())

    def test_batch_check_layer_availability(self):
        self.request("batch_check_layer_availability", "BatchCheckLayerAvailability", layerDigests=[DIGEST])

    def test_initiate_layer_upload(self):
        self.request("initiate_layer_upload", "InitiateLayerUpload")

    def test_upload_layer_part(self):
        self.request("upload_layer_part", "UploadLayerPart", uploadId=UPLOAD_ID,
                     partFirstByte=0, partLastByte=len(PART) - 1, layerPartBlob=PART)
        # Model evidence only: do not allocate or claim a full 20 MiB upload.
        shape = self.client.meta.service_model.shape_for("LayerPartBlob")
        self.assertEqual((shape.type_name, shape.metadata["max"]), ("blob", 20 * 1024 * 1024))

    def test_complete_layer_upload(self):
        self.request("complete_layer_upload", "CompleteLayerUpload", uploadId=UPLOAD_ID, layerDigests=[DIGEST])

    def test_put_image(self):
        self.request("put_image", "PutImage", imageManifest=MANIFEST, imageManifestMediaType=MEDIA_TYPE,
                     imageTag="fixture", imageDigest="sha256:" + hashlib.sha256(MANIFEST.encode()).hexdigest())

    def test_offline_guards_and_environment_restoration(self):
        with self.assertRaises(PermissionError):
            socket.socket()
        with patch.dict(os.environ, {"AWS_PROFILE": "must-not-load", "AWS_ENDPOINT_URL": "https://invalid.invalid"}):
            original = dict(os.environ)
            with isolated_aws_environment():
                self.assertNotIn("AWS_PROFILE", os.environ)
                self.assertNotIn("AWS_ENDPOINT_URL", os.environ)
                self.assertEqual(os.environ["AWS_CONFIG_FILE"], "/dev/null")
                self.assertEqual(os.environ["AWS_SHARED_CREDENTIALS_FILE"], "/dev/null")
            self.assertEqual(dict(os.environ), original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
