#!/usr/bin/env python3
"""One offline, connected ordinary ECR publication through the real Python owners.

Uses the retained catalog, encrypted AWS tuple, signed policy, private durable
artifact uploads, review receipt, generation guards, exact-request signer and
recipient envelope. Only gate health observations are substituted. Provider
ACKs are synthetic: this is not HTTP admission, Rust, SDK or AWS acceptance.
Run in the cached app image with network none, 2 CPUs, 2 GiB and TMPDIR=/tmp.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

import test_operator_catalog_aws as aws_fixture

ROOT = Path(__file__).resolve().parents[1]
workspace = aws_fixture.workspace
BINARY_DIGEST = "sha256:" + "6" * 64
SCOPE = {"registry_id": "123456789012", "region": "us-east-1",
    "repository_name": "catchplate-fixture/image", "image_tag": "reviewed-1"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64url(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def assert_signature(plain, action, body):
    """Independent HMAC check: retained AWS material signed these exact bytes."""
    assert set(plain) == {"apiVersion", "method", "scheme", "authority", "path", "query",
        "bodySha256", "bodyLength", "headers"}
    assert (plain["method"], plain["scheme"], plain["authority"], plain["path"], plain["query"]) == (
        "POST", "https", "api.ecr.us-east-1.amazonaws.com", "/", "")
    assert (plain["bodySha256"], plain["bodyLength"]) == (digest(body), len(body))
    headers = plain["headers"]
    assert set(headers) == {"accept", "authorization", "content-type", "host", "x-amz-date", "x-amz-target"}
    assert headers["accept"] == "*/*"
    assert headers["host"] == plain["authority"]
    assert headers["content-type"] == "application/x-amz-json-1.1"
    assert headers["x-amz-target"] == "AmazonEC2ContainerRegistry_V20150921." + action
    names = sorted(set(headers) - {"authorization"})
    signed_names = ";".join(names)
    canonical = ("POST\n/\n\n" + "".join(name + ":" + headers[name] + "\n" for name in names)
        + "\n" + signed_names + "\n" + hashlib.sha256(body).hexdigest()).encode("ascii")
    date = headers["x-amz-date"][:8]
    scope = date + "/us-east-1/ecr/aws4_request"
    signing_string = ("AWS4-HMAC-SHA256\n" + headers["x-amz-date"] + "\n" + scope + "\n"
        + hashlib.sha256(canonical).hexdigest()).encode("ascii")
    key = ("AWS4" + aws_fixture.SECRET).encode("ascii")
    for part in (date, "us-east-1", "ecr", "aws4_request"):
        key = hmac.new(key, part.encode("ascii"), hashlib.sha256).digest()
    expected = ("AWS4-HMAC-SHA256 Credential=" + aws_fixture.ACCESS + "/" + scope
        + ", SignedHeaders=" + signed_names + ", Signature="
        + hmac.new(key, signing_string, hashlib.sha256).hexdigest())
    assert hmac.compare_digest(headers["authorization"], expected)
    assert aws_fixture.SECRET not in encoded(plain).decode("ascii")
    assert not {"secret_access_key", "access_key_id", "session_token", "credentials"} & set(plain)


def connected():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from catchplate import ecr_image_artifact as artifact, ecr_publication_policy as policy
    from catchplate import operator_ecr_artifacts as uploads, operator_ecr_publications as owner
    from catchplate import operator_ecr_signing_api as api, operator_publication

    f = aws_fixture.Fixture()
    assert owner.readiness(), "ordinary owner bootstrap and private artifact root must be ready"
    created = f.create()
    credential = created["credential"]
    application_result = f.call(f.mutations.create_application, f.inputs.ApplicationInput(
        **f.review(), name="Offline ECR publisher", token_lifetime_seconds=3600), aws_fixture.ACTOR)
    application = application_result["application"]
    f.private.append(application_result["client_token"])

    # This is the only substituted production observation: no gate is running.
    def observed_gate():
        return {"ok": True, "policy_hash": f.store.get_policy_high_water()["policy_hash"],
            "operator_ecr_publication": dict(policy.GATE_DESCRIPTOR)}

    with patch.object(f.store, "loaded_gate_status", side_effect=observed_gate), \
            patch.object(f.store, "loaded_policy_hash", return_value=None):
        saved = f.mutations.create_ecr_rule(f.inputs.AwsEcrRuleInput(**f.review(),
            name="One reviewed image", application_id=application["id"], credential_id=credential["id"],
            operation_bundle="aws_ecr_publish_v1", approval_mode="host_review_v1", **SCOPE), aws_fixture.ACTOR)
    rule = saved["access_rule"]
    signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert signed["routes"][0]["adapter"]["type"] == policy.ADAPTER
    policy_hash = f.store.get_policy_high_water()["policy_hash"]

    # The API imports the real app for its configured binary identity; no
    # lifespan/server startup is performed, and the audit hook forbids sockets.
    from catchplate import app
    assert app.EXPECTED_DATA_PLANE_BINARY_DIGEST == BINARY_DIGEST

    config_bytes = b'{"architecture":"amd64","os":"linux"}'
    layer = b"connected-ecr-image-raw-blob-canary"
    def descriptor(media, raw):
        return {"mediaType": media, "digest": digest(raw), "size": len(raw)}
    manifest = encoded({"schemaVersion": 2, "mediaType": artifact.OCI_MANIFEST,
        "config": descriptor(artifact.OCI_CONFIG, config_bytes),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar", layer)]})
    blobs = {digest(config_bytes): config_bytes, digest(layer): layer}
    image = artifact.verify_image(manifest, {key: io.BytesIO(raw) for key, raw in blobs.items()})
    principal = application["principal_id"]
    publication = owner.create(application["id"], rule["id"], policy_hash, image.manifest.digest,
        image.commitment_sha256, principal_id=principal)
    identifier = publication["id"]
    store = uploads.configured_store()
    assert store.begin(identifier) == identifier
    owner.require_client(principal, identifier, staging=True)
    store.write_manifest(identifier, manifest)
    for key, raw in blobs.items():
        # Exercise ordered raw uploads, not pre-created files or a marker-only fixture.
        half = len(raw) // 2
        for offset, part in ((0, raw[:half]), (half, raw[half:])):
            owner.require_client(principal, identifier, staging=True)
            receipt = store.append_part(identifier, key, offset, part)
            assert receipt["uploaded_bytes"] == offset + len(part)
    assert all(item["complete"] for item in store.summary(identifier)["blobs"])
    with store.finalize(identifier) as sealed:
        assert owner.finalize_stage(identifier, sealed)["status"] == "awaiting_review"
    review = owner.review(identifier, f.config.ADMIN_USER_ID)
    assert review["publication"]["artifact"] == image.commitment()
    approved = owner.decide(identifier, f.config.ADMIN_USER_ID, {
        "decision": "approve", "note": None, "review_receipt_id": review["review_receipt_id"],
        "review_digest": review["review_digest"]})
    assert approved["status"] == "approved"
    held = store.recapture(identifier)
    try:
        active = owner.activate(identifier, held, principal_id=principal)
    except BaseException:
        held.close()
        raise
    assert active["status"] == "active"

    common = {"publicationId": identifier, "principalId": principal, "routeId": rule["route_id"],
        "credentialId": credential["id"], "policyHash": policy_hash}
    context = api.context({"apiVersion": api.CONTEXT_VERSION, **common})
    generation = context["credentialVersion"]
    assert generation == credential["credential_generation"] == 1
    returned = [publication, review, approved, active, context]

    def signing_request(action, **fields):
        body = encoded({"registryId": SCOPE["registry_id"], "repositoryName": SCOPE["repository_name"], **fields})
        recipient = X25519PrivateKey.generate()
        public = recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        nonce = b64url(os.urandom(32))
        wire = {"apiVersion": api.RESERVE_VERSION, **common, "childId": str(uuid.uuid4()),
            "expectedCredentialVersion": generation, "dataPlaneBinaryDigest": BINARY_DIGEST,
            "action": action, "bodyBase64": base64.b64encode(body).decode("ascii"), "bodySha256": digest(body),
            "recipientPublicKey": b64url(public), "recipientKeyId": digest(public), "recipientNonce": nonce,
            "maxTtlSeconds": 5}
        return wire, recipient, body

    # Both the public signing path and the real encrypted opener refuse a
    # generation mismatch, without consuming a child or modifying publication.
    wrong, _, _ = signing_request("BatchCheckLayerAvailability", layerDigests=list(blobs))
    wrong["expectedCredentialVersion"] = generation + 1
    before = owner.status(identifier, principal)
    try:
        api.reserve(wrong, wrong["recipientNonce"])
    except (api.SigningUnavailable, owner.PublicationConflict):
        pass
    else:
        raise AssertionError("wrong generation signed")
    assert owner.status(identifier, principal) == before
    with operator_publication.exclusive(), f.db.metadata_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            f.db.open_operator_ecr_credentials(conn, credential["id"], expected_version=generation + 1)
        except f.db.MetadataStoreError:
            pass
        else:
            raise AssertionError("wrong generation opened")
        assert conn.execute("SELECT COUNT(*) FROM operator_ecr_child_ids").fetchone()[0] == 0

    actions = set()
    def send(action, ack, **fields):
        wire, recipient, body = signing_request(action, **fields)
        envelope = api.reserve(wire, wire["recipientNonce"])
        current = owner.status(identifier, principal)
        assert current["child"]["status"] == "possible_send"
        aad = {key: value for key, value in envelope.items() if key not in
            {"serverEphemeralPublicKey", "aeadNonce", "ciphertext", "ciphertextSha256"}}
        ciphertext = unb64url(envelope["ciphertext"])
        assert digest(ciphertext) == envelope["ciphertextSha256"]
        shared = recipient.exchange(X25519PublicKey.from_public_bytes(unb64url(envelope["serverEphemeralPublicKey"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64url(wire["recipientNonce"]),
            info=b"catchplate:credential-lease-envelope:v2\0" + hashlib.sha256(encoded(aad)).digest()).derive(shared)
        plain = json.loads(AESGCM(key).decrypt(unb64url(envelope["aeadNonce"]), ciphertext, encoded(aad)))
        assert plain["apiVersion"] == api.SIGNED_VERSION
        assert_signature(plain, action, body)
        assert envelope["requestBindingSha256"] == digest(encoded(wire))
        response = encoded(ack)
        result = api.finish({"apiVersion": api.FINISH_VERSION, **common, "childId": wire["childId"],
            "expectedCredentialVersion": generation, "requestBindingSha256": digest(encoded(wire)),
            "outcome": "response", "statusCode": 200, "responseBodyBase64": base64.b64encode(response).decode("ascii")})
        assert result["acknowledged"] is True
        assert result["responseReleaseAllowed"] is True
        assert result["requestBodySha256"] == digest(body)
        assert result["responseBodySha256"] == digest(response)
        returned.extend((envelope, result))
        actions.add(action)
        return result

    try:
        send("BatchCheckLayerAvailability", {"layers": [{"layerDigest": key,
            "layerAvailability": "UNAVAILABLE"} for key in blobs]}, layerDigests=list(blobs))
        for key, raw in blobs.items():
            upload = str(uuid.uuid4())
            send("InitiateLayerUpload", {"uploadId": upload, "partSize": 10 * 1024 * 1024})
            send("UploadLayerPart", {"uploadId": upload, "lastByteReceived": len(raw) - 1},
                uploadId=upload, partFirstByte=0, partLastByte=len(raw) - 1,
                layerPartBlob=base64.b64encode(raw).decode("ascii"))
            send("CompleteLayerUpload", {"uploadId": upload, "layerDigest": key},
                uploadId=upload, layerDigests=[key])
        result = send("PutImage", {"image": {"imageId": {"imageDigest": image.manifest.digest,
            "imageTag": SCOPE["image_tag"]}}}, imageManifest=manifest.decode("ascii"), imageTag=SCOPE["image_tag"])
        assert result["status"] == "published"
        final = owner.status(identifier, principal)
        assert final["status"] == "published" and final["progress"]["calls"] == 8
        assert identifier not in owner._HANDLES
        assert len(actions) == 5
        with f.db.metadata_connection() as conn:
            assert conn.execute("SELECT COUNT(*) FROM operator_ecr_child_ids").fetchone()[0] == 8
            persisted = str([tuple(row) for row in conn.execute("SELECT * FROM operator_ecr_publications")])
            assert layer.decode() not in persisted and base64.b64encode(layer).decode() not in persisted
        f.privacy([*returned, final])
        workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert not aws_fixture.NETWORK_ATTEMPTS
        return {"status": "published", "actions": len(actions), "signed_children": 8,
            "wrong_generation_refused": True, "network_attempts": 0}
    finally:
        owner._drop(identifier)


class EcrConnectedTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.pop("PYTHONOPTIMIZE", None)
        artifacts = Path(self.scratch.name) / "artifacts"
        artifacts.mkdir(mode=0o700)
        self.environment.update(CATCHPLATE_ECR_ARTIFACT_ROOT=str(artifacts),
            CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST=BINARY_DIGEST,
            CATCHPLATE_OPERATOR_DEMO_UPSTREAMS='["https://api.ecr.us-east-1.amazonaws.com"]')

    def test_real_catalog_artifact_review_and_signing_reach_published(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail("connected ECR worker refused: " + aws_fixture.shared.worker_failure_summary(result))
        self.assertLessEqual(len(result.stdout), 8192)
        self.assertEqual(json.loads(result.stdout), {"status": "published", "actions": 5,
            "signed_children": 8, "wrong_generation_refused": True, "network_attempts": 0})


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        os.umask(0o077)
        try:
            outcome = connected()
        except Exception as error:
            print(json.dumps(aws_fixture.shared.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)
