#!/usr/bin/env python3
"""Ordinary ECR owner transaction/recovery tests, no AWS or deployment effects.

Real SQLite transactions, sealed image custody, protocol and reducer are used.
Catalog/authentication observations and the process publication flock are fixture
doubles; these checks do not claim live SDK/provider interoperability.
"""
from contextlib import closing, contextmanager, nullcontext
from copy import deepcopy
import base64
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_image_artifact as artifact
from serverware import ecr_image_custody as custody
from serverware import ecr_publication_plan as planner
from serverware import operator_ecr_publications as owner
from serverware import operator_publication


def prohibit_network(event, args):
    if event.startswith("socket."):
        raise PermissionError("ECR owner tests forbid sockets and DNS")


sys.addaudithook(prohibit_network)


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="serverware-ecr-owner-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "owner.sqlite3"
        self.clock = planner.Clock(1_800_000_000, 1_000_000_000)
        self.boot = str(uuid.uuid4())
        self.binding = {"application_id": str(uuid.uuid4()), "access_rule_id": str(uuid.uuid4()),
            "principal_id": "agent:fixture", "route_id": "operator.fixture", "credential_id": str(uuid.uuid4()),
            "credential_generation": 1, "credential_expires_at_epoch_ms": None, "policy_hash": "sha256:" + "1" * 64,
            "token_version": 1, "token_sha256": "sha256:" + "2" * 64,
            "token_expires_at_epoch_ms": (self.clock.unix_seconds + 3600) * 1000,
            "rule_sha256": "sha256:" + "3" * 64,
            "scope": {"registry_id": "123456789012", "region": "us-east-1",
                "repository_name": "serverware-fixture", "image_tag": "reviewed"}}
        self.wire = {key: self.binding[key] for key in
            ("principal_id", "route_id", "credential_id", "credential_generation", "policy_hash")}
        self.wire["request_binding_sha256"] = "sha256:" + "4" * 64
        self.database = SimpleNamespace(metadata_connection=self.connection, append_audit_event=self.audit)
        self.patches = [patch.object(owner, "_profile", return_value=(self.database, SimpleNamespace(ADMIN_USER_ID="admin"))),
            patch.object(owner, "_clock", side_effect=lambda: self.clock),
            patch.object(owner, "_boot", side_effect=lambda: self.boot),
            patch.object(owner, "_binding", side_effect=lambda *args: deepcopy(self.binding)),
            patch.object(operator_publication, "exclusive", side_effect=lambda **kwargs: nullcontext()),
            patch.object(operator_publication, "assert_held", return_value=None)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.close_handles)
        with self.connection() as conn:
            conn.execute("CREATE TABLE audit (event_type TEXT NOT NULL, event_json TEXT NOT NULL)")
            conn.execute("BEGIN IMMEDIATE")
            owner.initialize(conn)
        config, layer = b'{"architecture":"amd64","os":"linux"}', b"actual-image-blob-canary"
        def descriptor(media, raw):
            return {"mediaType": media, "digest": digest(raw), "size": len(raw)}
        self.raw = encoded({"schemaVersion": 2, "mediaType": artifact.OCI_MANIFEST,
            "config": descriptor(artifact.OCI_CONFIG, config),
            "layers": [descriptor("application/vnd.oci.image.layer.v1.tar", layer)]})
        self.blobs = {digest(config): config, digest(layer): layer}
        self.image = artifact.verify_image(self.raw, {key: io.BytesIO(raw) for key, raw in self.blobs.items()})

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.path)) as conn:
            conn.row_factory = sqlite3.Row
            with conn:
                yield conn

    def audit(self, conn, **kwargs):
        conn.execute("INSERT INTO audit VALUES(?,?)", (kwargs["event_type"], encoded(kwargs["event"]).decode()))

    def close_handles(self):
        for identifier in list(owner._HANDLES):
            owner._drop(identifier)

    def capture(self):
        return custody.capture(self.raw, {key: io.BytesIO(raw) for key, raw in self.blobs.items()})

    def create(self):
        return owner.create(self.binding["application_id"], self.binding["access_rule_id"],
            self.binding["policy_hash"], self.image.manifest.digest, self.image.commitment_sha256,
            principal_id=self.binding["principal_id"])

    def staged(self):
        item = self.create()
        with self.capture() as held:
            return owner.finalize_stage(item["id"], held)

    def approved(self):
        item = self.staged()
        review = owner.review(item["id"], "admin")
        return owner.decide(item["id"], "admin", {"decision": "approve", "note": None,
            **{key: review[key] for key in ("review_receipt_id", "review_digest")}})

    def active(self):
        item = self.approved()
        return owner.activate(item["id"], self.capture(), principal_id=self.binding["principal_id"])

    def request(self, identifier, action, *, child_id=None, **fields):
        body = encoded({"registryId": self.binding["scope"]["registry_id"],
            "repositoryName": self.binding["scope"]["repository_name"], **fields})
        return owner.reserve(identifier, child_id=child_id or str(uuid.uuid4()), action=action, body=body, **self.wire)

    def send(self, reservation, response, status=200):
        with owner.signing_transaction(reservation.child_id, publication_id=reservation.publication_id, **self.wire) as (conn, signed):
            self.assertTrue(conn.in_transaction)
            self.assertEqual(signed.body, reservation.body)
            self.assertEqual(signed.request_binding_sha256, self.wire["request_binding_sha256"])
        return owner.finish(reservation.child_id, publication_id=reservation.publication_id, status=status, body=encoded(response), **self.wire)

    def restart(self):
        self.close_handles()
        owner._PROCESS = str(uuid.uuid4())
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            owner.initialize(conn)

    def test_review_is_whole_exact_artifact_and_receipt_is_one_use(self):
        item = self.staged()
        self.assertEqual(item["artifact"], self.image.commitment())
        self.assertNotIn("token_sha256", encoded(item).decode())
        with self.assertRaises(owner.PublicationConflict):
            owner.review(item["id"], "wrong-reviewer")
        review = owner.review(item["id"], "admin")
        value = {"decision": "approve", "note": None, "review_digest": review["review_digest"],
            "review_receipt_id": review["review_receipt_id"]}
        bad = {**value, "review_digest": "sha256:" + "f" * 64}
        with self.assertRaises(owner.PublicationConflict):
            owner.decide(item["id"], "admin", bad)
        self.assertEqual(owner.decide(item["id"], "admin", value)["status"], "approved")
        with self.assertRaises(owner.PublicationConflict):
            owner.decide(item["id"], "admin", value)

    def test_manifest_commitment_mismatch_cannot_stage(self):
        item = owner.create(self.binding["application_id"], self.binding["access_rule_id"], self.binding["policy_hash"],
            "sha256:" + "0" * 64, self.image.commitment_sha256)
        with self.capture() as held, self.assertRaises(owner.PublicationConflict):
            owner.finalize_stage(item["id"], held)
        self.assertEqual(owner.status(item["id"], "admin")["status"], "staging")

    def test_full_five_action_publication_and_no_secret_or_raw_body_storage(self):
        item = self.active()
        request = self.request(item["id"], "BatchCheckLayerAvailability", layerDigests=list(self.blobs))
        self.send(request, {"layers": [{"layerDigest": key, "layerAvailability": "UNAVAILABLE"}
            for key in self.blobs]})
        for key, raw in self.blobs.items():
            upload = str(uuid.uuid4())
            self.send(self.request(item["id"], "InitiateLayerUpload"), {"uploadId": upload, "partSize": 10 * 1024 * 1024})
            self.send(self.request(item["id"], "UploadLayerPart", uploadId=upload,
                partFirstByte=0, partLastByte=len(raw) - 1, layerPartBlob=base64.b64encode(raw).decode()),
                {"uploadId": upload, "lastByteReceived": len(raw) - 1})
            self.send(self.request(item["id"], "CompleteLayerUpload", uploadId=upload, layerDigests=[key]),
                {"uploadId": upload, "layerDigest": key})
        result = self.send(self.request(item["id"], "PutImage", imageManifest=self.raw.decode(), imageTag="reviewed"),
            {"image": {"imageId": {"imageDigest": self.image.manifest.digest, "imageTag": "reviewed"}}})
        self.assertEqual(result["status"], "published")
        self.assertEqual(result["progress"]["calls"], 8)
        self.assertEqual(result["child"]["status"], "acknowledged")
        self.assertNotIn(item["id"], owner._HANDLES)
        with self.connection() as conn:
            values = str([tuple(row) for row in conn.execute("SELECT * FROM operator_ecr_publications")])
            self.assertNotIn("actual-image-blob-canary", values)
            self.assertNotIn(base64.b64encode(b"actual-image-blob-canary").decode(), values)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM operator_ecr_child_ids").fetchone()[0], 8)

    def test_one_pending_and_one_shot_signing_and_ack(self):
        item = self.active()
        reserved = self.request(item["id"], "InitiateLayerUpload")
        with self.assertRaises(owner.PublicationConflict):
            self.request(item["id"], "InitiateLayerUpload")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass
        with self.assertRaises(owner.PublicationConflict):
            with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
                pass
        result = owner.finish(reserved.child_id, publication_id=item["id"], status=200,
            body=encoded({"uploadId": str(uuid.uuid4()), "partSize": 1024}), **self.wire)
        self.assertEqual(result["status"], "active")
        with self.assertRaises(owner.PublicationConflict):
            owner.finish(reserved.child_id, publication_id=item["id"], status=200, body=b"{}", **self.wire)

    def test_old_child_uuid_cannot_be_reused_after_other_ack(self):
        item = self.active()
        def check(child=None):
            request = self.request(item["id"], "BatchCheckLayerAvailability", child_id=child, layerDigests=list(self.blobs))
            self.send(request, {"layers": [{"layerDigest": key, "layerAvailability": "AVAILABLE"} for key in self.blobs]})
            return request.child_id
        first = check()
        check()
        with self.assertRaises(owner.PublicationConflict):
            check(first)

    def test_possible_send_cannot_downgrade_failure_or_replay(self):
        item = self.active()
        reserved = self.request(item["id"], "InitiateLayerUpload")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass
        self.assertEqual(owner.fail(reserved.child_id, publication_id=item["id"], before_send=True, **self.wire)["status"], "uncertain")
        with self.assertRaises(owner.PublicationConflict):
            self.request(item["id"], "InitiateLayerUpload")

    def test_invalid_write_ack_is_uncertain_read_error_is_failed(self):
        item = self.active()
        self.assertEqual(self.send(self.request(item["id"], "InitiateLayerUpload"), {}, status=500)["status"], "uncertain")
        item = self.active()
        self.assertEqual(self.send(self.request(item["id"], "BatchCheckLayerAvailability", layerDigests=list(self.blobs)),
            {}, status=500)["status"], "failed")

    def test_restart_pending_is_terminal_and_acked_requires_explicit_resume(self):
        pending, acknowledged = self.active(), self.active()
        self.request(pending["id"], "InitiateLayerUpload")
        self.send(self.request(acknowledged["id"], "InitiateLayerUpload"),
            {"uploadId": str(uuid.uuid4()), "partSize": 1024})
        checkpoint = owner.status(acknowledged["id"], "admin")["progress"]
        self.restart()
        self.assertEqual(owner.status(pending["id"], "admin")["status"], "uncertain")
        self.assertEqual(owner.status(acknowledged["id"], "admin")["status"], "suspended")
        resumed = owner.activate(acknowledged["id"], self.capture())
        self.assertEqual(resumed["progress"], checkpoint)
        self.assertEqual(resumed["expires_at_epoch_ms"], acknowledged["expires_at_epoch_ms"])

    def test_boot_change_or_dual_deadline_never_refreshes_grant(self):
        item = self.active()
        self.boot = str(uuid.uuid4())
        self.restart()
        self.assertEqual(owner.status(item["id"], "admin")["status"], "expired")
        item = self.active()
        self.clock = planner.Clock(self.clock.unix_seconds, self.clock.monotonic_ns + 1800_000_000_000)
        with self.assertRaises(owner.PublicationExpired):
            self.request(item["id"], "InitiateLayerUpload")
        self.assertEqual(owner.status(item["id"], "admin")["status"], "expired")

    def test_current_token_policy_generation_and_parent_binding_are_rechecked(self):
        item = self.active()
        original = deepcopy(self.binding)
        for key, value in (("token_version", 2), ("token_sha256", "sha256:" + "f" * 64),
                ("credential_generation", 2), ("policy_hash", "sha256:" + "f" * 64)):
            self.binding[key] = value
            with self.assertRaises(owner.PublicationConflict):
                self.request(item["id"], "InitiateLayerUpload")
            self.binding = deepcopy(original)
        reserved = self.request(item["id"], "InitiateLayerUpload")
        self.binding["token_version"] = 2
        with self.assertRaises(owner.PublicationConflict):
            with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
                pass
        self.assertEqual(owner.fail(reserved.child_id, publication_id=item["id"], before_send=True, **self.wire)["status"], "failed")

    def test_audit_failure_rolls_back_decision_and_possible_send(self):
        item = self.staged()
        review = owner.review(item["id"], "admin")
        value = {"decision": "approve", "note": None,
            **{key: review[key] for key in ("review_receipt_id", "review_digest")}}
        def block(enabled):
            with self.connection() as conn:
                conn.execute("CREATE TRIGGER audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END"
                    if enabled else "DROP TRIGGER audit_failure")
        block(True)
        with self.assertRaises(sqlite3.IntegrityError):
            owner.decide(item["id"], "admin", value)
        block(False)
        self.assertEqual(owner.decide(item["id"], "admin", value)["status"], "approved")
        owner.activate(item["id"], self.capture())
        reserved = self.request(item["id"], "InitiateLayerUpload")
        block(True)
        with self.assertRaises(sqlite3.IntegrityError):
            with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
                pass
        block(False)
        self.assertEqual(owner.status(item["id"], "admin")["child"]["status"], "reserved")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass

    def test_wrong_actor_scope_binding_and_stage_tampering_are_refused(self):
        item = self.active()
        with self.assertRaises(owner.PublicationConflict):
            owner.status(item["id"], "other-client")
        self.assertEqual(owner.list_publications("other-client"), [])
        with self.assertRaises(owner.PublicationConflict):
            owner.require_client(self.binding["principal_id"], item["id"], staging=True)
        reserved = self.request(item["id"], "InitiateLayerUpload")
        with self.assertRaises(owner.PublicationConflict):
            with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **{**self.wire,
                    "request_binding_sha256": "sha256:" + "f" * 64}):
                pass
        self.assertEqual(owner.fail(reserved.child_id, publication_id=item["id"], before_send=True, **self.wire)["status"], "failed")
        item = self.active()
        with self.assertRaises(ValueError):
            self.request(item["id"], "BatchCheckLayerAvailability", layerDigests=["sha256:" + "f" * 64])
        self.assertEqual(owner.status(item["id"], "admin")["status"], "failed")

    def test_parent_lifetime_respects_shorter_client_and_aws_session(self):
        self.binding["token_expires_at_epoch_ms"] = (self.clock.unix_seconds + 100) * 1000 + 999
        self.binding["credential_expires_at_epoch_ms"] = (self.clock.unix_seconds + 60) * 1000
        item = self.create()
        self.assertEqual(item["expires_at_epoch_ms"], (self.clock.unix_seconds + 60) * 1000)

    def test_expired_active_slot_releases_owned_content_before_replacement(self):
        old = self.active()
        held = owner._HANDLES[old["id"]].image
        self.clock = planner.Clock(self.clock.unix_seconds + 1801, self.clock.monotonic_ns + 1801_000_000_000)
        self.create()
        self.assertNotIn(old["id"], owner._HANDLES)
        with self.assertRaises(custody.CustodyError):
            held.image
        self.assertEqual(owner.status(old["id"], "admin")["status"], "expired")

    def test_authority_change_after_valid_intermediate_ack_preserves_effect_evidence(self):
        item = self.active()
        reserved = self.request(item["id"], "InitiateLayerUpload")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass
        self.binding["credential_generation"] = 2
        response = encoded({"uploadId": str(uuid.uuid4()), "partSize": 1024})
        result = owner.finish(reserved.child_id, publication_id=item["id"], status=200, body=response, **self.wire)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["terminal_reason"], "authority_changed_after_send")
        self.assertEqual(result["child"]["status"], "acknowledged")
        self.assertEqual(result["child"]["response_sha256"], digest(response))
        self.assertEqual(result["progress"]["calls"], 1)
        self.assertIsNotNone(result["progress"]["upload"])
        self.assertNotIn(item["id"], owner._HANDLES)
        with self.assertRaises(owner.PublicationConflict):
            self.request(item["id"], "InitiateLayerUpload")
        with self.connection() as conn:
            audit = json.loads(conn.execute("SELECT event_json FROM audit WHERE event_type=? ORDER BY rowid DESC LIMIT 1",
                ("operator.ecr_publication.acknowledged",)).fetchone()[0])
        self.assertTrue(audit["authority_changed"])
        self.assertEqual(audit["response_sha256"], digest(response))

    def test_authority_change_after_valid_final_ack_still_records_published_image(self):
        item = self.active()
        self.send(self.request(item["id"], "BatchCheckLayerAvailability", layerDigests=list(self.blobs)),
            {"layers": [{"layerDigest": key, "layerAvailability": "AVAILABLE"} for key in self.blobs]})
        reserved = self.request(item["id"], "PutImage", imageManifest=self.raw.decode(), imageTag="reviewed")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass
        self.binding["token_version"] = 2
        response = encoded({"image": {"imageId": {"imageDigest": self.image.manifest.digest, "imageTag": "reviewed"}}})
        result = owner.finish(reserved.child_id, publication_id=item["id"], status=200, body=response, **self.wire)
        self.assertEqual(result["status"], "published")
        self.assertEqual(result["terminal_reason"], "authority_changed_after_send")
        self.assertEqual(result["child"]["status"], "acknowledged")
        self.assertEqual(result["child"]["response_sha256"], digest(response))
        self.assertEqual(result["progress"]["calls"], 2)

    def test_wrong_publication_id_cannot_sign_finish_or_fail_child(self):
        item = self.active()
        reserved = self.request(item["id"], "InitiateLayerUpload")
        wrong = str(uuid.uuid4())
        with self.assertRaises(owner.PublicationConflict):
            with owner.signing_transaction(reserved.child_id, publication_id=wrong, **self.wire):
                pass
        with self.assertRaises(owner.PublicationConflict):
            owner.fail(reserved.child_id, publication_id=wrong, before_send=True, **self.wire)
        self.assertEqual(owner.status(item["id"], "admin")["child"]["status"], "reserved")
        with owner.signing_transaction(reserved.child_id, publication_id=item["id"], **self.wire):
            pass
        with self.assertRaises(owner.PublicationConflict):
            owner.finish(reserved.child_id, publication_id=wrong, status=200,
                body=encoded({"uploadId": str(uuid.uuid4()), "partSize": 1024}), **self.wire)
        self.assertEqual(owner.status(item["id"], "admin")["child"]["status"], "possible_send")


if __name__ == "__main__":
    unittest.main()
