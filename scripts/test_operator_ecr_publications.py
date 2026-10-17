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
from catchplate import ecr_image_artifact as artifact
from catchplate import ecr_image_custody as custody
from catchplate import ecr_publication_plan as planner
from catchplate import operator_ecr_publications as owner
from catchplate import operator_ecr_artifacts as artifacts
from catchplate import operator_publication


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
        self.temp = tempfile.TemporaryDirectory(prefix="catchplate-ecr-owner-")
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
                "repository_name": "catchplate-fixture", "image_tag": "reviewed"}}
        self.wire = {key: self.binding[key] for key in
            ("principal_id", "route_id", "credential_id", "credential_generation", "policy_hash")}
        self.wire["request_binding_sha256"] = "sha256:" + "4" * 64
        self.database = SimpleNamespace(metadata_connection=self.connection, append_audit_event=self.audit)
        self.patches = [patch.object(owner, "_profile", return_value=(self.database, SimpleNamespace(ADMIN_USER_ID="admin", DB_PATH=self.path))),
            patch.object(owner, "_clock", side_effect=lambda: self.clock),
            patch.object(owner, "_boot", side_effect=lambda: self.boot),
            patch.object(owner, "_binding", side_effect=lambda *args, **kwargs: deepcopy(self.binding)),
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
        self.assertEqual(owner.status(item["id"], "admin")["status"], "expired")
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

    def denied(self):
        item = self.staged()
        review = owner.review(item["id"], "admin")
        return owner.decide(item["id"], "admin", {"decision": "deny", "note": "fixture denial",
            **{key: review[key] for key in ("review_receipt_id", "review_digest")}})

    def retired_store(self, identifier):
        root = Path(self.temp.name) / ("artifacts-" + identifier)
        root.mkdir(mode=0o700)
        store = artifacts.ArtifactStore(root, max_stages=1)
        store.begin(identifier)
        store.write_manifest(identifier, self.raw)
        for key, raw in self.blobs.items():
            store.append_part(identifier, key, 0, raw)
        with store.finalize(identifier):
            pass
        return store, root

    def test_explicit_retirement_reclaims_stage_and_preserves_terminal_evidence(self):
        before = self.denied()
        store, root = self.retired_store(before["id"])
        with patch.object(artifacts, "configured_store", return_value=store):
            retired = owner.retire_artifacts(before["id"], "admin")
            repeated = owner.retire_artifacts(before["id"], "admin")
        self.assertTrue(retired["artifacts_retired"])
        self.assertEqual(retired["artifact_retirement_status"], "retired")
        self.assertEqual(retired, repeated)
        self.assertEqual({key: retired[key] for key in ("status", "artifact", "progress", "child", "terminal_reason", "decision_note")},
            {key: before[key] for key in ("status", "artifact", "progress", "child", "terminal_reason", "decision_note")})
        self.assertFalse((root / before["id"]).exists())
        replacement = store.begin()
        self.assertTrue((root / replacement).is_dir())
        with self.connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM operator_ecr_publications").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit WHERE event_type LIKE '%artifacts_retir%'").fetchone()[0], 2)

    def test_partial_retirement_requires_explicit_retry_and_never_repeats_authority(self):
        item = self.denied()
        store, root = self.retired_store(item["id"])
        calls = []
        def incomplete(identifier, **kwargs):
            calls.append(identifier)
            self.assertEqual(owner.status(identifier, "admin")["artifact_retirement_status"], "pending")
            result = store.retire(identifier, **kwargs)
            if len(calls) == 1:
                raise RuntimeError("synthetic response loss after cleanup")
            return result
        with patch.object(artifacts, "configured_store", return_value=SimpleNamespace(retire=incomplete)):
            with self.assertRaises(RuntimeError):
                owner.retire_artifacts(item["id"], "admin")
            pending = owner.status(item["id"], "admin")
            self.assertEqual(pending["artifact_retirement_status"], "pending")
            self.assertFalse(pending["artifacts_retired"])
            self.restart()
            self.assertEqual(owner.status(item["id"], "admin")["artifact_retirement_status"], "pending")
            self.assertEqual(len(calls), 1)  # Startup does not retry cleanup.
            self.assertEqual(owner.retire_artifacts(item["id"], "admin")["artifact_retirement_status"], "retired")
        self.assertEqual(len(calls), 2)
        self.assertFalse((root / item["id"]).exists())
        with self.connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit WHERE event_type LIKE '%artifacts_retir%'").fetchone()[0], 2)

    def test_retirement_refuses_nonadmin_active_uncertain_and_possible_send(self):
        active = self.active()
        denied = self.denied()
        with patch.object(artifacts, "configured_store") as configured:
            for identifier, actor in ((denied["id"], self.binding["principal_id"]), (active["id"], "admin")):
                with self.assertRaises(owner.PublicationConflict):
                    owner.retire_artifacts(identifier, actor)
            pending = self.request(active["id"], "InitiateLayerUpload")
            with owner.signing_transaction(pending.child_id, publication_id=active["id"], **self.wire):
                pass
            owner.fail(pending.child_id, publication_id=active["id"], **self.wire)
            with self.assertRaises(owner.PublicationConflict):
                owner.retire_artifacts(active["id"], "admin")
            # A read failure has no known write effect, but its possible-send
            # marker is deliberately still ineligible for artifact removal.
            read = self.active()
            request = self.request(read["id"], "BatchCheckLayerAvailability", layerDigests=list(self.blobs))
            result = self.send(request, {}, status=500)
            self.assertEqual(result["status"], "failed")
            with self.assertRaises(owner.PublicationConflict):
                owner.retire_artifacts(read["id"], "admin")
            configured.assert_not_called()

    def test_expired_projection_becomes_durable_before_retirement(self):
        item = self.active()
        self.clock = planner.Clock(self.clock.unix_seconds + 1801, self.clock.monotonic_ns + 1801_000_000_000)
        self.assertEqual(owner.status(item["id"], "admin")["status"], "expired")
        def retire(identifier, **kwargs):
            with self.connection() as conn:
                self.assertEqual(conn.execute("SELECT status FROM operator_ecr_publications WHERE id=?", (identifier,)).fetchone()[0], "expired")
            return {"stage_id": identifier, "retired": True, "removed_files": 0, "removed_bytes": 0}
        with patch.object(artifacts, "configured_store", return_value=SimpleNamespace(retire=retire)):
            result = owner.retire_artifacts(item["id"], "admin")
        self.assertEqual(result["status"], "expired")
        self.assertTrue(result["artifacts_retired"])

    def test_retirement_audit_failure_prevents_cleanup_and_completion_can_retry(self):
        item = self.denied()
        store, root = self.retired_store(item["id"])
        with self.connection() as conn:
            conn.execute("CREATE TRIGGER audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with patch.object(artifacts, "configured_store", return_value=store) as configured:
            with self.assertRaises(sqlite3.IntegrityError):
                owner.retire_artifacts(item["id"], "admin")
            configured.assert_not_called()
        self.assertTrue((root / item["id"]).exists())
        self.assertEqual(owner.status(item["id"], "admin")["artifact_retirement_status"], "available")
        with self.connection() as conn:
            conn.execute("DROP TRIGGER audit_failure")
            conn.execute("CREATE TRIGGER audit_failure BEFORE INSERT ON audit WHEN NEW.event_type='operator.ecr_publication.artifacts_retired' "
                "BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with patch.object(artifacts, "configured_store", return_value=store):
            with self.assertRaises(sqlite3.IntegrityError):
                owner.retire_artifacts(item["id"], "admin")
            self.assertFalse((root / item["id"]).exists())
            self.assertEqual(owner.status(item["id"], "admin")["artifact_retirement_status"], "pending")
            with self.connection() as conn:
                conn.execute("DROP TRIGGER audit_failure")
            self.assertTrue(owner.retire_artifacts(item["id"], "admin")["artifacts_retired"])

    def test_indexed_keyset_pages_preserve_tied_timestamps_and_actor_isolation(self):
        identifiers = [self.denied()["id"] for _ in range(23)]
        expected = sorted(identifiers, reverse=True)
        actual, cursor = [], None
        while True:
            page = owner.list_publications_page("admin", before=cursor)
            self.assertLessEqual(len(page["publications"]), 10)
            actual.extend(row["id"] for row in page["publications"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
            self.assertEqual(cursor, page["publications"][-1]["id"])
        self.assertEqual(actual, expected)
        self.assertEqual(owner.list_publications_page("other-client")["publications"], [])
        with self.assertRaises(owner.PublicationConflict):
            owner.list_publications_page("other-client", before=identifiers[0])
        for limit in (0, 11, True):
            with self.assertRaises(owner.PublicationConflict):
                owner.list_publications_page("admin", limit=limit)
        with self.connection() as conn:
            detail = " ".join(row[3] for row in conn.execute("EXPLAIN QUERY PLAN SELECT * FROM operator_ecr_publications "
                "WHERE (created_at_epoch_ms,id)<(?,?) ORDER BY created_at_epoch_ms DESC,id DESC LIMIT 11",
                (self.clock.unix_seconds * 1000, identifiers[0])))
        self.assertIn("operator_ecr_publications_page", detail)

    def test_retained_history_is_not_a_lifetime_creation_limit(self):
        original = self.denied()
        with self.connection() as conn:
            row = dict(conn.execute("SELECT * FROM operator_ecr_publications WHERE id=?", (original["id"],)).fetchone())
            columns = list(row)
            for _ in range(1024):
                row["id"] = str(uuid.uuid4())
                conn.execute("INSERT INTO operator_ecr_publications(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")",
                    [row[column] for column in columns])
        item = self.create()
        self.assertEqual(item["status"], "staging")
        self.assertEqual(len(owner.list_publications_page("admin")["publications"]), 10)
        self.restart()
        self.assertEqual(owner.status(item["id"], "admin")["status"], "staging")

    def test_artifact_begin_failure_terminalizes_only_the_matching_staging_parent(self):
        item = self.create()
        with self.assertRaises(owner.PublicationConflict):
            owner.fail_staging(item["id"], "wrong-client")
        failed = owner.fail_staging(item["id"], self.binding["principal_id"])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["terminal_reason"], "artifact_staging_failed")
        self.assertEqual(owner.fail_staging(item["id"], self.binding["principal_id"]), failed)
        active = self.active()
        with self.assertRaises(owner.PublicationConflict):
            owner.fail_staging(active["id"], self.binding["principal_id"])

    def test_notification_pending_is_read_only_current_and_review_scoped(self):
        item = self.staged()
        def projection(*, reviewer=None, now=None, query_only=True):
            with self.connection() as conn:
                if query_only:
                    conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                before = conn.total_changes
                result = owner.notification_pending(conn, item["id"], reviewer_id=reviewer,
                    now_epoch_ms=self.clock.unix_seconds * 1000 if now is None else now)
                self.assertEqual(conn.total_changes, before)
                return result
        result = projection()
        self.assertEqual(result["publication_id"], item["id"])
        self.assertEqual(result["reviewer_id"], "admin")
        self.assertNotIn("token_sha256", encoded(result).decode())
        self.assertIsNone(projection(reviewer="different-admin"))
        self.assertIsNone(projection(query_only=False))
        self.assertIsNone(projection(now=item["expires_at_epoch_ms"]))
        self.binding["token_version"] += 1
        self.assertIsNone(projection())
        self.binding["token_version"] -= 1
        receipt = owner.review(item["id"], "admin")
        owner.decide(item["id"], "admin", {"decision": "deny", "note": None,
            **{key: receipt[key] for key in ("review_receipt_id", "review_digest")}})
        self.assertIsNone(projection())

    def test_readonly_aws_public_binding_checks_generation_and_never_reads_secrets(self):
        from catchplate import operator_catalog_aws as aws
        identifier, subject = self.binding["credential_id"], str(uuid.uuid4())
        metadata = {"provider_id": "operator-demo", "provider_subject": subject, "secret_class": aws.SECRET_CLASS,
            "connection_type": aws.CONNECTION, "credential_kind": "long_term", "expires_at": None}
        record = {"name": "Synthetic AWS public metadata", "auth_type": aws.KIND, "header_name": None,
            "connection_type": aws.CONNECTION, "provider_subject": subject, "credential_kind": "long_term",
            "expires_at": None, "status": "active", "version": 1}
        with self.connection() as conn:
            # Deliberately no ciphertext/secret columns exist in this fixture:
            # the notification-only helper can succeed using public data alone.
            conn.execute("CREATE TABLE credentials (id TEXT PRIMARY KEY,name TEXT,kind TEXT,metadata TEXT,lifecycle_status TEXT,credential_version INTEGER)")
            conn.execute("CREATE TABLE operator_catalog_credentials (id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT)")
            conn.execute("CREATE TABLE credential_generations (credential_id TEXT PRIMARY KEY,last_version INTEGER)")
            conn.execute("INSERT INTO credentials VALUES(?,?,?,?,?,?)", (identifier, record["name"], aws.KIND, encoded(metadata).decode(), "active", 1))
            conn.execute("INSERT INTO operator_catalog_credentials VALUES(?,?,?)", (identifier, 1, encoded(record).decode()))
            conn.execute("INSERT INTO credential_generations VALUES(?,?)", (identifier, 1))
        def observe():
            with self.connection() as conn:
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                result = owner._aws_public_current(conn, identifier)
                self.assertEqual(conn.total_changes, 0)
                return result
        self.assertEqual(observe()[1], metadata)
        with self.connection() as conn:
            conn.execute("UPDATE credential_generations SET last_version=2")
        with self.assertRaises(owner.PublicationConflict):
            observe()
        with self.connection() as conn:
            conn.execute("UPDATE credential_generations SET last_version=1")
            conn.execute("UPDATE credentials SET lifecycle_status='revoked'")
        with self.assertRaises(owner.PublicationConflict):
            observe()


if __name__ == "__main__":
    unittest.main()
