"""Deterministic local fixtures and actual stock SDK serialization; no sockets."""
import base64
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import publish as example
from serverware.ecr_artifact_staging import stage_artifact

example.isolate_environment()
# Import first: urllib3 performs an optional local IPv6 capability probe.
import boto3
from botocore.awsrequest import AWSResponse
from botocore.httpsession import get_cert_path


def prohibit_network(event, _args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Offline ECR client tests forbid network and subprocesses")


sys.addaudithook(prohibit_network)
APP = "12345678-1234-4234-8234-123456789abc"
RULE = "00000000-0000-4000-8000-000000000002"
PUBLICATION = "00000000-0000-4000-8000-000000000003"
TOKEN = "synthetic-private-proxy-token:@/?#%"


class FakeControl:
    def __init__(self, owner, state="staging"):
        self.owner, self.state, self.calls = owner, state, []

    def call(self, method, suffix="", body=None, *, binary=False):
        self.calls.append((method, suffix, body, binary))
        if suffix.endswith("/submit"):
            self.state = "awaiting_review"
        if suffix.endswith("/activate"):
            self.state = "active"
        return self.owner.dto(self.state)


class Raw:
    def __init__(self, raw):
        self.raw = raw

    def stream(self, amt=None, decode_content=False):
        yield self.raw


class ClientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="serverware-ecr-example-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.vector = json.loads((example.ROOT / "scripts/fixtures/ecr_image_artifact_v1.json").read_bytes())
        self.source = self.directory / "source"
        blobs = self.source / "blobs/sha256"
        blobs.mkdir(parents=True)
        self.manifest = self.vector["manifest"].encode("utf-8")
        self.manifest_digest = self.vector["expected_commitment"]["manifest"]["digest"]
        (blobs / self.manifest_digest[7:]).write_bytes(self.manifest)
        self.blobs = {item["digest"]: item["utf8"].encode("utf-8") for item in self.vector["blobs"]}
        for name, raw in self.blobs.items():
            (blobs / name[7:]).write_bytes(raw)
        self.stage_path = self.directory / "stage"
        stage_artifact(self.source, self.stage_path, self.manifest_digest)
        self.ca = self.directory / "ca.pem"
        self.ca.write_bytes(re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(get_cert_path(True)).read_bytes(), re.S).group())
        self.config_path = self.directory / "client.private.json"
        self.config = {"schema": example.SCHEMA, "operation_bundle": "aws_ecr_publish_v1",
            "application_id": APP, "access_rule_id": RULE, "expected_policy_hash": "sha256:" + "1" * 64,
            "registry_id": "123456789012", "region": "us-east-1", "repository_name": "fixture/repository",
            "image_tag": "reviewed", "proxy_url": "https://proxy.example.test:8443",
            "control_api_url": "https://proxy.example.test:8443/v1/ecr/publications",
            "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP, "proxy_password": TOKEN,
            "ca_file": "ca.pem", "proxy_ca_file": "ca.pem", "token_expires_at_epoch_ms": 2**53 - 1}
        self.config_path.write_text(json.dumps(self.config))
        self.loaded = example.load_configuration(self.config_path)
        self.expires_at = time.time_ns() // 1_000_000 + 120000

    def dto(self, state):
        return {"schema": "serverware.ecrPublication/v1", "id": PUBLICATION, "status": state,
            "assurance": "host-trusted", "application_id": APP, "access_rule_id": RULE,
            "policy_hash": self.config["expected_policy_hash"],
            "scope": {key: self.config[key] for key in example.SCOPE_FIELDS},
            "manifest_digest": self.manifest_digest,
            "artifact_sha256": self.vector["expected_commitment_sha256"],
            "artifact": None if state == "staging" else self.vector["expected_commitment"],
            "expires_at_epoch_ms": self.expires_at, "revision": 1,
            "decision_note": TOKEN, "terminal_reason": TOKEN}

    def test_configuration_and_all_ambient_credentials_are_separate(self):
        example.check_versions()
        self.assertEqual(self.loaded["ca_file"], str(self.ca))
        self.assertIn("synthetic-private-proxy-token%3A%40%2F%3F%23%25", self.loaded["_proxy_url"])
        with patch.dict(os.environ, {"AWS_PROFILE": "bad", "AWS_ENDPOINT_URL": "https://bad.invalid",
                "BOTO_CONFIG": "/bad", "HTTPS_PROXY": "https://bad.invalid", "SSL_CERT_FILE": "/bad"}):
            example.isolate_environment()
            self.assertNotIn("AWS_PROFILE", os.environ)
            self.assertNotIn("HTTPS_PROXY", os.environ)
            self.assertNotIn("SSL_CERT_FILE", os.environ)
            self.assertEqual(os.environ["AWS_CONFIG_FILE"], "/dev/null")
        for key, value in (("schema", "wrong"), ("control_api_url", "https://elsewhere.test/v1/ecr/publications"),
                ("proxy_username", RULE), ("token_expires_at_epoch_ms", 1), ("registry_id", "wrong"),
                ("region", "cn-north-1"), ("repository_name", "../escape"), ("image_tag", "has whitespace"),
                ("proxy_url", "http://proxy.example.test"), ("proxy_password", TOKEN + "\n")):
            with self.subTest(key=key):
                self.config_path.write_text(json.dumps({**self.config, key: value}))
                with self.assertRaises(example.ClientError) as caught:
                    example.load_configuration(self.config_path)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_stage_reverifies_and_seals_original_bytes(self):
        with example.open_stage(self.stage_path) as sealed:
            self.assertEqual(sealed.image.manifest_bytes, self.manifest)
            name, raw = next(iter(self.blobs.items()))
            (self.stage_path / "blobs" / name[7:]).write_bytes(b"different")
            self.assertEqual(sealed.read_blob(name, 0, len(raw)), raw)
        with self.assertRaises(Exception):
            with example.open_stage(self.stage_path):
                pass

    def test_stage_raw_upload_then_review_without_sdk(self):
        control, created = FakeControl(self), []
        with example.open_stage(self.stage_path) as sealed, patch.object(example, "sdk_client", side_effect=AssertionError("No SDK during staging")):
            with patch.object(example, "PART_BYTES", 5):
                result = example.stage(self.loaded, sealed, control, created.append)
        self.assertEqual(result["status"], "awaiting_review")
        self.assertEqual(created[0]["id"], PUBLICATION)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertEqual(json.loads(control.calls[0][2]), {"application_id": APP, "access_rule_id": RULE,
            "expected_policy_hash": self.config["expected_policy_hash"], "manifest_digest": self.manifest_digest,
            "artifact_sha256": self.vector["expected_commitment_sha256"]})
        self.assertEqual(control.calls[1][2], self.manifest)
        self.assertEqual(control.calls[-1], ("POST", "/" + PUBLICATION + "/submit", b"{}", False))
        actual = {}
        for method, path, body, binary in control.calls[2:-1]:
            self.assertTrue(binary)
            name, offset = path.split("/blobs/")[1].split("/parts/")
            self.assertEqual(int(offset), len(actual.get("sha256:" + name, b"")))
            self.assertLessEqual(len(body), 5)
            actual["sha256:" + name] = actual.get("sha256:" + name, b"") + body
        self.assertEqual(actual, self.blobs)

    def test_wrong_publication_scope_and_unapproved_writes_fail_before_sdk(self):
        for state in ("staging", "awaiting_review", "active", "suspended", "denied", "expired", "uncertain", "published"):
            with self.subTest(state=state), example.open_stage(self.stage_path) as sealed:
                with patch.object(example, "sdk_client", side_effect=AssertionError("Must not construct SDK")):
                    with self.assertRaises(example.ClientError):
                        example.publish(self.loaded, PUBLICATION, sealed, FakeControl(self, state), True)
        with example.open_stage(self.stage_path) as sealed:
            control = FakeControl(self, "approved")
            with self.assertRaises(example.ClientError):
                example.publish(self.loaded, PUBLICATION, sealed, control)
            self.assertEqual(control.calls, [])
            for key, value in (("id", RULE), ("policy_hash", "sha256:" + "2" * 64), ("application_id", RULE),
                    ("manifest_digest", "sha256:" + "3" * 64), ("artifact_sha256", "sha256:" + "4" * 64)):
                with self.assertRaises(example.ClientError):
                    example.publication({**self.dto("approved"), key: value}, self.loaded, PUBLICATION, sealed.image)

    @contextmanager
    def sdk(self, fault=None, available=False):
        calls, uploads = [], {}
        with example.sdk_client(self.loaded, PUBLICATION) as client:
            self.assertEqual(client.meta.config.retries["total_max_attempts"], 1)
            self.assertEqual(client.meta.config.proxies_config["proxy_ca_bundle"], str(self.ca))
            self.assertEqual(client._endpoint.http_session._verify, str(self.ca))
            self.assertFalse(client.meta.config.proxies_config["proxy_use_forwarding_for_https"])

            def send(request):
                headers = {name.lower(): value.decode("ascii") if isinstance(value, bytes) else value for name, value in request.headers.items()}
                self.assertEqual(request.url, "https://api.ecr.us-east-1.amazonaws.com/")
                self.assertEqual(request.method, "POST")
                self.assertIn("ServerwarePublication/" + PUBLICATION, headers["user-agent"])
                self.assertIn("Credential=" + example.CLIENT_ACCESS + "/", headers["authorization"])
                self.assertNotIn(TOKEN, json.dumps(headers))
                self.assertNotIn("proxy-authorization", headers)
                self.assertNotIn("x-amz-security-token", headers)
                body = json.loads(request.body)
                self.assertEqual(body["registryId"], self.config["registry_id"])
                self.assertEqual(body["repositoryName"], self.config["repository_name"])
                action = headers["x-amz-target"].split(".")[-1]
                calls.append((action, body))
                if fault == action:
                    raise RuntimeError(TOKEN)
                if action == "BatchCheckLayerAvailability":
                    result = {"layers": [{"layerDigest": name, "layerAvailability": "AVAILABLE" if available else "UNAVAILABLE"} for name in body["layerDigests"]]}
                elif action == "InitiateLayerUpload":
                    upload_id = "00000000-0000-4000-8000-" + str(len(uploads) + 1).zfill(12)
                    uploads[upload_id] = bytearray()
                    result = {"uploadId": upload_id, "partSize": 5}
                elif action == "UploadLayerPart":
                    received = uploads[body["uploadId"]]
                    part = base64.b64decode(body["layerPartBlob"], validate=True)
                    self.assertEqual(body["partFirstByte"], len(received))
                    received.extend(part)
                    self.assertEqual(body["partLastByte"], len(received) - 1)
                    result = {"uploadId": body["uploadId"], "lastByteReceived": len(received) - 1}
                elif action == "CompleteLayerUpload":
                    name = body["layerDigests"][0]
                    self.assertEqual(bytes(uploads[body["uploadId"]]), self.blobs[name])
                    result = {"uploadId": body["uploadId"], "layerDigest": name}
                else:
                    self.assertEqual(action, "PutImage")
                    self.assertEqual(body["imageManifest"].encode("utf-8"), self.manifest)
                    self.assertEqual(body["imageDigest"], self.manifest_digest)
                    self.assertEqual(body["imageTag"], "reviewed")
                    result = {"image": {"imageId": {"imageDigest": self.manifest_digest, "imageTag": "reviewed"}}}
                status = 200
                if fault == "http500" and action == "InitiateLayerUpload":
                    status, result = 500, {"__type": "ServerException", "message": TOKEN}
                if fault == "wrong-digest" and action == "PutImage":
                    result["image"]["imageId"]["imageDigest"] = "sha256:" + "f" * 64
                if fault == "wrong-offset" and action == "UploadLayerPart":
                    result["lastByteReceived"] += 1
                raw = json.dumps(result).encode()
                return AWSResponse(request.url, status, {"Content-Type": "application/x-amz-json-1.1"}, Raw(raw))

            with patch.object(client._endpoint.http_session, "send", side_effect=send):
                yield client, calls

    def test_actual_stock_sdk_all_five_actions_and_exact_bytes(self):
        with example.open_stage(self.stage_path) as sealed, self.sdk() as (client, calls):
            result = example.upload(self.loaded, PUBLICATION, sealed, client, self.dto("active")["expires_at_epoch_ms"])
        self.assertEqual(result["status"], "published")
        self.assertEqual({name for name, _ in calls}, example.protocol.ACTIONS)
        self.assertEqual(result["sdk_calls"], len(calls))

    def test_existing_blobs_skip_upload_but_exact_put_is_required(self):
        with example.open_stage(self.stage_path) as sealed, self.sdk(available=True) as (client, calls):
            example.upload(self.loaded, PUBLICATION, sealed, client, self.dto("active")["expires_at_epoch_ms"])
        self.assertEqual([name for name, _ in calls], ["BatchCheckLayerAvailability", "PutImage"])

    def test_expiry_and_unknown_write_stop_without_sdk_retry(self):
        with example.open_stage(self.stage_path) as sealed, self.sdk(fault="InitiateLayerUpload") as (client, calls):
            with self.assertRaises(example.ClientError):
                example.upload(self.loaded, PUBLICATION, sealed, client, 1)
            self.assertEqual(calls, [])
            with self.assertRaises(RuntimeError):
                example.upload(self.loaded, PUBLICATION, sealed, client, self.dto("active")["expires_at_epoch_ms"])
            self.assertEqual([name for name, _ in calls], ["BatchCheckLayerAvailability", "InitiateLayerUpload"])

    def test_real_sdk_provider_error_and_mismatched_ack_do_not_retry(self):
        for fault, last in (("http500", "InitiateLayerUpload"), ("wrong-offset", "UploadLayerPart"), ("wrong-digest", "PutImage")):
            with self.subTest(fault=fault), example.open_stage(self.stage_path) as sealed, self.sdk(fault=fault) as (client, calls):
                with self.assertRaises(Exception):
                    example.upload(self.loaded, PUBLICATION, sealed, client, self.expires_at)
                self.assertEqual(calls[-1][0], last)
                self.assertEqual(sum(name == last for name, _ in calls), 1)

    def test_activation_is_explicit_after_local_sdk_prerequisites(self):
        control = FakeControl(self, "approved")
        with example.open_stage(self.stage_path) as sealed, self.sdk() as (client, calls):
            @contextmanager
            def selected(*_):
                self.assertEqual([row[0] for row in control.calls], ["GET"])
                yield client
            with patch.object(example, "sdk_client", selected):
                result = example.publish(self.loaded, PUBLICATION, sealed, control, True)
        self.assertEqual(result["status"], "published")
        self.assertEqual([(row[0], row[1]) for row in control.calls], [("GET", "/" + PUBLICATION), ("POST", "/" + PUBLICATION + "/activate")])

    def test_control_basic_auth_direct_tls_bounds_and_redacted_failure(self):
        control = example.Control(self.loaded)
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def read(self, amount):
                self.amount = amount
                return json.dumps({"ok": True}).encode()
        response = Response()
        with patch.object(control.opener, "open", return_value=response) as opened:
            self.assertEqual(control.call("GET", "/" + PUBLICATION), {"ok": True})
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, self.config["control_api_url"] + "/" + PUBLICATION)
        self.assertEqual(base64.b64decode(request.headers["Authorization"].split()[1]).decode(), APP + ":" + TOKEN)
        self.assertEqual(opened.call_args.kwargs, {"timeout": 30})
        self.assertEqual(response.amount, example.CONTROL_RESPONSE_BYTES + 1)
        with patch.object(control.opener, "open", side_effect=RuntimeError(TOKEN)) as opened:
            with self.assertRaises(example.ClientError) as caught:
                control.call("POST", "/" + PUBLICATION + "/activate", b"{}")
        self.assertEqual(opened.call_count, 1)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(TOKEN, str(caught.exception))
        with self.assertRaises(example.ClientError):
            example.NoRedirect().redirect_request(None, None, 302, None, None, "https://elsewhere.test")

    def test_cli_sanitizes_failure_and_never_implicitly_publishes(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(example.Control, "call", side_effect=RuntimeError(TOKEN)), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(example.main(["status", "--config", str(self.config_path), "--publication", PUBLICATION]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(TOKEN, err.getvalue())
        self.assertIn("nothing was retried", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
