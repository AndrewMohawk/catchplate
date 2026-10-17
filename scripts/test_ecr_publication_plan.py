#!/usr/bin/env python3
"""Pure ECR planner controls, not durable CAS, approval, custody or AWS success.

Fixtures use the real content verifier and protocol parsers. The read callback
returns unchanged in-memory fixture bytes; this suite does not prove immutable
custody or detect a dishonest callback that substitutes both input and request.
No SDK, sockets,
credentials, storage owner, daemon, retry or publication side effect is involved.
Reusing an old pure input is not consumption: a future owner must supply durable
serialization, original authority/lifetime checks and one actual dispatch.
"""
from dataclasses import FrozenInstanceError
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def prohibit_network(event, _args):
    if event.startswith("socket."):
        raise PermissionError("planner tests forbid sockets and DNS")


sys.addaudithook(prohibit_network)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import ecr_image_artifact as artifact
from catchplate import ecr_publication_plan as planner
from catchplate import ecr_sdk_protocol as protocol


REGISTRY, REGION, REPOSITORY = "123456789012", "us-east-1", "catchplate-fixture"
NOW, MONO = 1_800_000_000, 10_000_000_000
MIB = 1024 * 1024
PART_SIZE = MIB + 17  # Two bounded comparison reads; no claimed AWS minimum.
CONFIG = b'{"architecture":"amd64","os":"linux","fixture":"public"}'
PREFIX = b"p" * PART_SIZE
FIRST_LAYER, SECOND_LAYER = PREFIX + b"first-tail", PREFIX + b"other-tail"
UPLOAD_ID = "00000000-0000-4000-8000-000000000001"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def image_fixture(*, config=CONFIG, layers=(FIRST_LAYER, SECOND_LAYER, FIRST_LAYER)):
    def descriptor(media, raw):
        return {"mediaType": media, "digest": digest(raw), "size": len(raw)}
    # Whitespace and field order intentionally differ from canonical JSON: the
    # publication must use these exact manifest bytes, not equivalent JSON.
    raw = json.dumps({"schemaVersion": 2, "mediaType": artifact.OCI_MANIFEST,
        "config": descriptor(artifact.OCI_CONFIG, config),
        "layers": [descriptor("application/vnd.oci.image.layer.v1.tar", data) for data in layers]},
        indent=1).encode() + b"\n"
    blobs = {digest(data): data for data in (config, *layers)}
    return artifact.verify_image(raw, {key: io.BytesIO(data) for key, data in blobs.items()}), blobs


def clock(seconds=0, nanos=None):
    return planner.Clock(unix_seconds=NOW + seconds,
        monotonic_ns=MONO + (seconds * 1_000_000_000 if nanos is None else nanos))


def scope(**changes):
    return planner.PublicationScope(**{"protocol_scope": protocol.Scope(
        registry_id=REGISTRY, region=REGION, repository_name=REPOSITORY),
        "publication_id": "publication:fixture", "principal_id": "principal:fixture",
        "route_id": "route:fixture", "credential_id": "credential:fixture",
        "credential_generation": 7, "policy_hash": "sha256:" + "1" * 64,
        "image_tag": "fixture-tag", **changes})


def request(action, *, target=None, **fields):
    target = target or protocol.Scope(registry_id=REGISTRY, region=REGION, repository_name=REPOSITORY)
    body = {"registryId": target.registry_id, "repositoryName": target.repository_name, **fields}
    return protocol.parse_request(scope=target, action=action, body=encoded(body))


def response(parsed, **fields):
    return protocol.parse_response(parsed, status=200, body=encoded(fields))


def availability(parsed, available, blobs, *, sizes=True):
    rows = [{"layerDigest": key, "layerAvailability": "AVAILABLE" if key in available else "UNAVAILABLE",
        **({"layerSize": len(blobs[key])} if sizes else {})} for key in parsed.layer_digests]
    return response(parsed, layers=rows, failures=[])


class EcrPublicationPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.blobs = image_fixture()

    def initial(self, *, image=None, selected_scope=None, lifetime=300):
        return planner.create(image or self.image, selected_scope or scope(), clock=clock(),
            deadline=planner.Deadline(unix_seconds=NOW + lifetime,
                monotonic_ns=MONO + lifetime * 1_000_000_000))

    def read_blob(self, key, offset, length):
        self.assertIs(type(offset), int)
        self.assertIs(type(length), int)
        self.assertGreaterEqual(offset, 0)
        self.assertGreater(length, 0)
        self.assertLessEqual(length, MIB)
        return self.blobs[key][offset:offset + length]

    def refuse(self, callback):
        with self.assertRaises(planner.PlanError) as caught:
            callback()
        self.assertNotIn("PRIVATE-CANARY", str(caught.exception))

    def mark_available(self, state, keys, *, now=None):
        now = now or clock()
        parsed = request("BatchCheckLayerAvailability", layerDigests=list(keys))
        pending, plan = planner.begin(state, parsed, clock=now)
        return planner.apply_response(pending, plan, availability(parsed, set(keys), self.blobs), clock=now)

    def initiate(self, state, *, upload_id=UPLOAD_ID, part_size=PART_SIZE, now=None):
        now = now or clock()
        parsed = request("InitiateLayerUpload")
        pending, plan = planner.begin(state, parsed, clock=now)
        return planner.apply_response(pending, plan,
            response(parsed, uploadId=upload_id, partSize=part_size), clock=now)

    def part_request(self, data, *, upload_id=UPLOAD_ID, offset=0):
        return request("UploadLayerPart", uploadId=upload_id, partFirstByte=offset,
            partLastByte=offset + len(data) - 1, layerPartBlob=base64.b64encode(data).decode())

    def part(self, state, data, *, upload_id=UPLOAD_ID, offset=0, now=None):
        now = now or clock()
        parsed = self.part_request(data, upload_id=upload_id, offset=offset)
        pending, plan = planner.begin(state, parsed, clock=now, read_blob=self.read_blob)
        return planner.apply_response(pending, plan, response(parsed, registryId=REGISTRY,
            repositoryName=REPOSITORY, uploadId=upload_id,
            lastByteReceived=offset + len(data) - 1), clock=now)

    def complete(self, state, key, *, upload_id=UPLOAD_ID):
        parsed = request("CompleteLayerUpload", uploadId=upload_id, layerDigests=[key])
        pending, plan = planner.begin(state, parsed, clock=clock())
        return planner.apply_response(pending, plan, response(parsed, registryId=REGISTRY,
            repositoryName=REPOSITORY, uploadId=upload_id, layerDigest=key), clock=clock())

    def put_request(self, **changes):
        return request("PutImage", **{"imageManifest": self.image.manifest_bytes.decode(),
            "imageManifestMediaType": self.image.manifest.media_type,
            "imageTag": "fixture-tag", "imageDigest": self.image.manifest.digest, **changes})

    def checkpoint_roundtrip(self, state):
        raw = planner.export_checkpoint(state)
        self.assertIs(type(raw), bytes)
        self.assertLess(len(raw), planner.MAX_CHECKPOINT_BYTES)
        document = json.loads(raw)
        self.assertEqual(document["schema"], planner.CHECKPOINT_SCHEMA)
        self.assertNotIn("_seal", document)
        self.assertNotIn("_plan", document)
        self.assertNotIn("_image", document)
        self.assertNotIn("imageManifest", document)
        # No replay and no content callback: restoration rejoins the verifier's
        # observation, while the durable owner must separately retain custody.
        with patch.object(planner, "begin", side_effect=AssertionError("replay")), \
                patch.object(planner, "apply_response", side_effect=AssertionError("replay")):
            restored = planner.restore_checkpoint(self.image, state.scope, raw,
                clock=state.clock, deadline=state.deadline)
        self.assertEqual(planner.export_checkpoint(restored), raw)
        self.assertIsNot(restored, state)
        self.assertIsNone(restored._plan)
        self.assertEqual(restored.deadline, state.deadline)
        return restored

    def checkpoint_refuses_document(self, state, document):
        self.refuse(lambda: planner.restore_checkpoint(self.image, state.scope, encoded(document),
            clock=state.clock, deadline=state.deadline))

    def test_checkpoints_roundtrip_each_acked_upload_phase_then_publish(self):
        state = self.checkpoint_roundtrip(self.initial())
        state = self.checkpoint_roundtrip(self.mark_available(state, [self.image.config.digest]))
        state = self.checkpoint_roundtrip(self.initiate(state))
        self.assertEqual(state.upload.parts, 0)
        state = self.checkpoint_roundtrip(self.part(state, PREFIX))
        self.assertEqual(len(state.upload.candidate_digests), 2)
        state = self.checkpoint_roundtrip(self.part(state, b"other-tail", offset=len(PREFIX)))
        self.assertEqual(state.upload.candidate_digests, (digest(SECOND_LAYER),))
        self.refuse(lambda: planner.begin(state, request("CompleteLayerUpload", uploadId=UPLOAD_ID,
            layerDigests=[digest(FIRST_LAYER)]), clock=clock()))
        state = self.checkpoint_roundtrip(self.complete(state, digest(SECOND_LAYER)))
        state = self.checkpoint_roundtrip(self.mark_available(state, [digest(FIRST_LAYER)]))
        parsed = self.put_request()
        pending, plan = planner.begin(state, parsed, clock=clock())
        # Essential ACK only: redundant response echoes are not invented.
        acknowledged = response(parsed, image={"imageId": {
            "imageDigest": self.image.manifest.digest, "imageTag": "fixture-tag"}})
        done = self.checkpoint_roundtrip(planner.apply_response(pending, plan, acknowledged, clock=clock()))
        self.assertEqual(done.status, "published")
        self.refuse(lambda: planner.begin(done, request("InitiateLayerUpload"), clock=clock()))
        with self.assertRaises(FrozenInstanceError):
            done.status = "active"

    def test_checkpoint_all_uploaded_and_all_available_histories_preserve_counters(self):
        state = self.initial()
        for number, data in enumerate((SECOND_LAYER, CONFIG, FIRST_LAYER), start=1):
            upload_id = "00000000-0000-4000-8000-" + str(number).zfill(12)
            state = self.checkpoint_roundtrip(self.initiate(state, upload_id=upload_id))
            for offset in range(0, len(data), PART_SIZE):
                state = self.checkpoint_roundtrip(self.part(state, data[offset:offset + PART_SIZE],
                    upload_id=upload_id, offset=offset))
            state = self.checkpoint_roundtrip(self.complete(state, digest(data), upload_id=upload_id))
        self.assertEqual(state.calls, 11)
        self.assertEqual(state.revision, 22)
        self.assertEqual(state.part_bytes, self.image.total_blob_bytes)
        available = self.checkpoint_roundtrip(self.mark_available(self.initial(), sorted(self.blobs)))
        self.assertEqual((available.calls, available.part_bytes, available.comparison_bytes,
            available.comparison_calls), (1, 0, 0, 0))
        with patch.object(planner, "MAX_CALLS", available.calls):
            restored = self.checkpoint_roundtrip(available)
            self.refuse(lambda: planner.begin(restored, self.put_request(), clock=clock()))

    def test_checkpoint_retains_original_deadlines_and_advances_only_nonregressing_clock(self):
        state = self.mark_available(self.initial(lifetime=10), [self.image.config.digest], now=clock(2))
        raw = planner.export_checkpoint(state)
        restored = planner.restore_checkpoint(self.image, state.scope, raw,
            clock=clock(3), deadline=state.deadline)
        self.assertEqual(restored.clock, clock(3))
        self.assertEqual(restored.deadline, state.deadline)
        self.assertEqual(restored.calls, state.calls)
        for observed in (clock(1, 3_000_000_000), clock(3, 1_000_000_000),
                clock(10, 9_000_000_000), clock(9, 10_000_000_000), object()):
            self.refuse(lambda: planner.restore_checkpoint(self.image, state.scope, raw,
                clock=observed, deadline=state.deadline))
        for change in (-1, 1):
            for deadline in (planner.Deadline(state.deadline.unix_seconds + change,
                    state.deadline.monotonic_ns), planner.Deadline(state.deadline.unix_seconds,
                    state.deadline.monotonic_ns + change)):
                self.refuse(lambda: planner.restore_checkpoint(self.image, state.scope, raw,
                    clock=clock(3), deadline=deadline))
        self.refuse(lambda: planner.begin(restored, request("InitiateLayerUpload"), clock=clock(2)))

    def test_checkpoint_rejoins_every_immutable_scope_field_and_actual_artifact(self):
        state = self.initial()
        raw = planner.export_checkpoint(state)
        for field, value in (("publication_id", "other"), ("principal_id", "other"),
                ("route_id", "other"), ("credential_id", "other"), ("credential_generation", 8),
                ("policy_hash", "sha256:" + "2" * 64), ("image_tag", "other-tag")):
            self.refuse(lambda: planner.restore_checkpoint(self.image, scope(**{field: value}), raw,
                clock=clock(), deadline=state.deadline))
        for target in (protocol.Scope("999999999999", REGION, REPOSITORY),
                protocol.Scope(REGISTRY, "us-west-2", REPOSITORY),
                protocol.Scope(REGISTRY, REGION, "other-repository")):
            self.refuse(lambda: planner.restore_checkpoint(self.image, scope(protocol_scope=target), raw,
                clock=clock(), deadline=state.deadline))
        other, _ = image_fixture(config=b"other-config", layers=(b"other-layer",))
        for candidate in (other, artifact.parse_manifest(self.image.manifest_bytes), object()):
            self.refuse(lambda: planner.restore_checkpoint(candidate, state.scope, raw,
                clock=clock(), deadline=state.deadline))
        for field in ("artifact_sha256", "manifest_digest"):
            self.checkpoint_refuses_document(state, {**json.loads(raw), field: "sha256:" + "0" * 64})

    def test_checkpoint_never_exports_or_restores_inflight_failed_or_uncertain_state(self):
        initial = self.initial()
        for action in ("InitiateLayerUpload", "BatchCheckLayerAvailability"):
            parsed = request(action, **({"layerDigests": [self.image.config.digest]}
                if action == "BatchCheckLayerAvailability" else {}))
            pending, plan = planner.begin(initial, parsed, clock=clock())
            self.refuse(lambda: planner.export_checkpoint(pending))
            self.refuse(lambda: planner.export_checkpoint(planner.fail(pending, plan, clock=clock())))
        for status in ("pending", "failed", "uncertain", "unknown", True, None):
            self.checkpoint_refuses_document(initial, {**json.loads(planner.export_checkpoint(initial)), "status": status})
        self.refuse(lambda: planner.export_checkpoint(object()))

    def test_checkpoint_json_is_bounded_closed_and_strict(self):
        state = self.initial()
        raw = planner.export_checkpoint(state)
        document = json.loads(raw)
        malformed = [b"", raw.decode(), bytearray(raw), b"\xff", b"[]", b"null",
            b" " * (planner.MAX_CHECKPOINT_BYTES + 1), b"[[[[[0]]]]]",
            b'{"x":' + b"9" * 100 + b"}", b"[" + b"0," * 2048 + b"0]",
            raw[:-1] + b',"schema":"duplicate"}', raw.replace(b'"calls":0', b'"calls":0.0'),
            raw.replace(b'"calls":0', b'"calls":NaN'), raw.replace(b'"calls":0', b'"calls":Infinity')]
        for bad in malformed:
            self.refuse(lambda: planner.restore_checkpoint(self.image, state.scope, bad,
                clock=clock(), deadline=state.deadline))
        for field in document:
            missing = {key: value for key, value in document.items() if key != field}
            self.checkpoint_refuses_document(state, missing)
        self.checkpoint_refuses_document(state, {**document, "unexpected": "PRIVATE-CANARY"})
        self.checkpoint_refuses_document(state, {**document, "schema": "catchplate.ecrPublicationCheckpoint/v2"})
        for field in ("revision", "calls", "part_bytes", "comparison_bytes", "comparison_calls"):
            self.checkpoint_refuses_document(state, {**document, field: True})
            self.checkpoint_refuses_document(state, {**document, field: -1})
        for field in ("clock", "deadline", "scope"):
            self.checkpoint_refuses_document(state, {**document, field: {**document[field], "extra": 0}})
        for field in ("clock", "deadline"):
            for component in ("unix_seconds", "monotonic_ns"):
                self.checkpoint_refuses_document(state, {**document,
                    field: {**document[field], component: True}})
        self.checkpoint_refuses_document(state, {**document,
            "scope": {**document["scope"], "credential_generation": True}})
        self.checkpoint_refuses_document(state, {**document, "scope": {**document["scope"],
            "protocol_scope": {**document["scope"]["protocol_scope"], "extra": 0}}})

    def test_checkpoint_rejects_inconsistent_counters_rosters_and_upload_shapes(self):
        state = self.part(self.initiate(self.mark_available(self.initial(), [self.image.config.digest])), PREFIX)
        original = json.loads(planner.export_checkpoint(state))
        for changes in ({"revision": state.revision + 1}, {"calls": state.calls + 1},
                {"calls": planner.MAX_CALLS + 1}, {"revision": 2, "calls": 1},
                {"part_bytes": len(PREFIX) - 1}, {"part_bytes": self.image.total_blob_bytes + 1},
                {"comparison_bytes": len(PREFIX) - 1}, {"comparison_bytes": planner.MAX_COMPARISON_BYTES + 1},
                {"comparison_bytes": 2 * len(PREFIX) - 1}, {"comparison_calls": 3},
                {"comparison_calls": 0}, {"comparison_calls": planner.MAX_COMPARISON_CALLS + 1},
                {"ready_digests": [self.image.config.digest] * 2},
                {"ready_digests": ["sha256:" + "0" * 64]}, {"seen_upload_ids": []},
                {"seen_upload_ids": [UPLOAD_ID, UPLOAD_ID]}, {"seen_upload_ids": ["invalid"]},
                {"upload": None}, {"status": "fresh"}, {"status": "published"}):
            self.checkpoint_refuses_document(state, {**original, **changes})
        upload = original["upload"]
        for changes in ({"extra": 0}, {"upload_id": "00000000-0000-4000-8000-000000000099"},
                {"candidate_digests": []}, {"candidate_digests": [self.image.config.digest]},
                {"candidate_digests": list(reversed(upload["candidate_digests"]))},
                {"acknowledged_offset": 0}, {"acknowledged_offset": len(PREFIX) - 1},
                {"acknowledged_offset": len(FIRST_LAYER) + 1}, {"parts": 0}, {"parts": 2},
                {"parts": True}, {"part_size": 0}, {"part_size": protocol.MAX_PART_BYTES + 1}):
            self.checkpoint_refuses_document(state, {**original, "upload": {**upload, **changes}})
        initial_upload = self.initiate(self.initial())
        initial_document = json.loads(planner.export_checkpoint(initial_upload))
        self.checkpoint_refuses_document(initial_upload, {**initial_document, "upload": {
            **initial_document["upload"], "candidate_digests": [self.image.config.digest]}})
        completed = self.complete(self.part(self.initiate(self.initial()), CONFIG), self.image.config.digest)
        completed_document = json.loads(planner.export_checkpoint(completed))
        self.checkpoint_refuses_document(completed, {**completed_document, "part_bytes": len(CONFIG) - 1})

    def test_create_binds_actual_verified_image_and_original_scope_deadline(self):
        state = self.initial()
        self.assertEqual(state.scope, scope())
        self.assertEqual(state.deadline, planner.Deadline(unix_seconds=NOW + 300,
            monotonic_ns=MONO + 300_000_000_000))
        self.assertEqual(state.clock, clock())
        self.assertEqual(state.artifact_sha256, self.image.commitment_sha256)
        self.assertEqual(state.manifest_digest, digest(self.image.manifest_bytes))
        self.assertEqual(len(self.image.layers), 3)
        self.assertEqual(len(self.image.blobs), 3)  # Repeated layer is not a second upload.
        self.assertEqual(state.status, "fresh")
        self.assertEqual((state.calls, state.part_bytes, state.comparison_bytes, state.comparison_calls), (0, 0, 0, 0))
        self.assertFalse(state.ready_digests)
        self.assertIsNone(state.upload)
        with self.assertRaises(FrozenInstanceError):
            state.status = "published"
        self.refuse(lambda: planner.create(artifact.parse_manifest(self.image.manifest_bytes), scope(),
            clock=clock(), deadline=state.deadline))
        self.refuse(lambda: planner.create(object(), scope(), clock=clock(), deadline=state.deadline))

    def test_scope_types_and_deadlines_are_closed_not_caller_extended(self):
        for changes in ({"credential_generation": True}, {"credential_generation": 0},
                {"credential_generation": 2 ** 53}, {"policy_hash": "sha256:" + "A" * 64},
                {"publication_id": ""}, {"principal_id": "line\nbreak"},
                {"route_id": "x" * 257}, {"credential_id": "with space"},
                {"image_tag": ""}, {"image_tag": "x" * 301}):
            with self.subTest(changes=tuple(changes)):
                self.refuse(lambda: self.initial(selected_scope=scope(**changes)))
        for wall, mono in ((NOW, MONO + 1), (NOW + 1, MONO), (True, MONO + 1), (NOW + 1, True)):
            self.refuse(lambda: planner.create(self.image, scope(), clock=clock(),
                deadline=planner.Deadline(unix_seconds=wall, monotonic_ns=mono)))

    def test_batch_subsets_are_read_only_config_stays_required(self):
        state = self.initial()
        layers = sorted({row.digest for row in self.image.layers})
        state = self.mark_available(state, layers)
        self.assertEqual(set(state.ready_digests), set(layers))
        self.assertEqual((state.calls, state.part_bytes, state.comparison_bytes), (1, 0, 0))
        self.refuse(lambda: planner.begin(state, self.put_request(), clock=clock()))
        state = self.mark_available(state, [self.image.config.digest])
        self.assertEqual(set(state.ready_digests), set(self.blobs))
        self.assertEqual(state.calls, 2)
        self.assertEqual(state.deadline, self.initial().deadline)
        self.refuse(lambda: planner.begin(state, request("BatchCheckLayerAvailability",
            layerDigests=["sha256:" + "9" * 64]), clock=clock()))

    def test_common_prefix_candidates_narrow_and_short_final_part_is_exact(self):
        state = self.mark_available(self.initial(), [self.image.config.digest])
        state = self.initiate(state)
        expected = {digest(FIRST_LAYER), digest(SECOND_LAYER)}
        self.assertEqual(set(state.upload.candidate_digests), expected)
        self.assertEqual(state.upload.acknowledged_offset, 0)
        state = self.part(state, PREFIX)
        self.assertEqual(set(state.upload.candidate_digests), expected)
        self.assertEqual(state.upload.acknowledged_offset, len(PREFIX))
        state = self.part(state, b"other-tail", offset=len(PREFIX))
        self.assertEqual(tuple(state.upload.candidate_digests), (digest(SECOND_LAYER),))
        self.assertEqual(state.upload.acknowledged_offset, len(SECOND_LAYER))
        self.refuse(lambda: planner.begin(state, request("CompleteLayerUpload", uploadId=UPLOAD_ID,
            layerDigests=[digest(FIRST_LAYER)]), clock=clock()))
        state = self.complete(state, digest(SECOND_LAYER))
        self.assertIn(digest(SECOND_LAYER), state.ready_digests)
        self.assertNotIn(digest(FIRST_LAYER), state.ready_digests)
        self.assertIsNone(state.upload)

    def test_arbitrary_upload_order_repeated_layers_and_original_manifest_publication(self):
        state = self.initial()
        for number, data in enumerate((SECOND_LAYER, CONFIG, FIRST_LAYER), start=1):
            upload_id = "00000000-0000-4000-8000-" + str(number).zfill(12)
            state = self.initiate(state, upload_id=upload_id)
            for offset in range(0, len(data), PART_SIZE):
                state = self.part(state, data[offset:offset + PART_SIZE],
                    upload_id=upload_id, offset=offset)
            state = self.complete(state, digest(data), upload_id=upload_id)
        self.assertEqual(set(state.ready_digests), set(self.blobs))
        self.assertEqual(state.part_bytes, sum(len(data) for data in self.blobs.values()))
        self.assertEqual(state.calls, 11)  # 3 initiate + 5 parts + 3 complete.
        parsed = self.put_request()
        pending, plan = planner.begin(state, parsed, clock=clock())
        self.assertEqual(plan.request.image_manifest, self.image.manifest_bytes)
        self.assertEqual(plan.request.image_tag, "fixture-tag")
        acknowledged = response(parsed, image={"registryId": REGISTRY, "repositoryName": REPOSITORY,
            "imageId": {"imageDigest": self.image.manifest.digest, "imageTag": "fixture-tag"},
            "imageManifest": self.image.manifest_bytes.decode(),
            "imageManifestMediaType": self.image.manifest.media_type})
        done = planner.apply_response(pending, plan, acknowledged, clock=clock())
        self.assertEqual(done.status, "published")
        self.assertEqual(done.calls, 12)
        self.assertEqual(done.deadline, self.initial().deadline)
        self.refuse(lambda: planner.begin(done, request("InitiateLayerUpload"), clock=clock()))

    def test_batch_unavailable_does_not_demote_ready_or_allow_check_during_upload(self):
        key = self.image.config.digest
        ready = self.mark_available(self.initial(), [key])
        parsed = request("BatchCheckLayerAvailability", layerDigests=[key])
        pending, plan = planner.begin(ready, parsed, clock=clock())
        self.refuse(lambda: planner.apply_response(pending, plan, availability(parsed, set(), self.blobs), clock=clock()))
        self.assertIn(key, pending.ready_digests)
        uploading = self.initiate(ready)
        self.refuse(lambda: planner.begin(uploading, parsed, clock=clock()))
        self.refuse(lambda: planner.begin(uploading, request("InitiateLayerUpload"), clock=clock()))

    def test_batch_declared_size_must_match_verified_original(self):
        key = self.image.config.digest
        parsed = request("BatchCheckLayerAvailability", layerDigests=[key])
        pending, plan = planner.begin(self.initial(), parsed, clock=clock())
        wrong = response(parsed, layers=[{"layerDigest": key, "layerAvailability": "AVAILABLE",
            "layerSize": len(CONFIG) + 1}], failures=[])
        self.refuse(lambda: planner.apply_response(pending, plan, wrong, clock=clock()))
        self.assertFalse(pending.ready_digests)
        # Optional size is not an excuse to demand undeclared provider fields.
        good = planner.apply_response(pending, plan, availability(parsed, {key}, self.blobs, sizes=False), clock=clock())
        self.assertEqual(set(good.ready_digests), {key})

    def test_offsets_are_contiguous_inclusive_and_nonfinal_size_is_exact(self):
        state = self.initiate(self.mark_available(self.initial(), [self.image.config.digest]))
        self.refuse(lambda: planner.begin(state, self.part_request(b"p"),
            clock=clock(), read_blob=self.read_blob))
        self.refuse(lambda: planner.begin(state, self.part_request(PREFIX, offset=1),
            clock=clock(), read_blob=self.read_blob))
        self.refuse(lambda: planner.begin(state, request("CompleteLayerUpload", uploadId=UPLOAD_ID,
            layerDigests=[digest(FIRST_LAYER)]), clock=clock()))
        state = self.part(state, PREFIX)
        for offset in (0, len(PREFIX) - 1, len(PREFIX) + 1):
            self.refuse(lambda: planner.begin(state, self.part_request(b"first-tail", offset=offset),
                clock=clock(), read_blob=self.read_blob))
        self.refuse(lambda: planner.begin(state,
            self.part_request(b"first-tail", offset=len(PREFIX),
                upload_id="00000000-0000-4000-8000-000000000002"),
            clock=clock(), read_blob=self.read_blob))
        final = self.part(state, b"first-tail", offset=len(PREFIX))
        self.assertEqual(final.upload.acknowledged_offset, len(FIRST_LAYER))
        self.refuse(lambda: planner.begin(final,
            self.part_request(b"!", offset=len(FIRST_LAYER)), clock=clock(), read_blob=self.read_blob))

    def test_pending_identity_old_plan_and_response_request_mismatch_refuse(self):
        initial = self.initial()
        parsed = request("BatchCheckLayerAvailability", layerDigests=[self.image.config.digest])
        pending, plan = planner.begin(initial, parsed, clock=clock())
        self.assertEqual(pending.status, "pending")
        self.assertEqual(plan.base_revision, initial.revision)
        self.assertEqual(plan.request_sha256, digest(parsed.body))
        self.assertIs(plan.request, parsed)
        self.refuse(lambda: planner.begin(pending, parsed, clock=clock()))
        twin = request("BatchCheckLayerAvailability", layerDigests=[self.image.config.digest])
        self.refuse(lambda: planner.apply_response(pending, plan,
            availability(twin, {self.image.config.digest}, self.blobs), clock=clock()))
        another_pending, another_plan = planner.begin(self.initial(), parsed, clock=clock())
        self.refuse(lambda: planner.apply_response(pending, another_plan,
            availability(parsed, {self.image.config.digest}, self.blobs), clock=clock()))
        response_value = availability(parsed, {self.image.config.digest}, self.blobs)
        ready = planner.apply_response(pending, plan, response_value, clock=clock())
        self.refuse(lambda: planner.apply_response(ready, plan, response_value, clock=clock()))
        self.refuse(lambda: planner.apply_response(another_pending, plan, response_value, clock=clock()))
        self.refuse(lambda: planner.apply_response(pending, plan, object(), clock=clock()))
        with self.assertRaises(FrozenInstanceError):
            plan.action = "PutImage"
        # The exact old immutable inputs still compute a result. This is NOT
        # a consumed ticket or durable single-dispatch guarantee.
        repeated = planner.apply_response(pending, plan, response_value, clock=clock())
        self.assertEqual(repeated.ready_digests, ready.ready_digests)
        self.assertEqual(repeated.revision, ready.revision)

    def test_put_requires_original_manifest_bytes_media_digest_and_tag(self):
        state = self.mark_available(self.initial(), sorted(self.blobs))
        for changes in ({"imageManifest": encoded(json.loads(self.image.manifest_bytes)).decode(),
                         "imageDigest": digest(encoded(json.loads(self.image.manifest_bytes)))},
                {"imageTag": "different-tag"},
                {"imageManifestMediaType": artifact.DOCKER_MANIFEST}):
            self.refuse(lambda: planner.begin(state, self.put_request(**changes), clock=clock()))
        pending, plan = planner.begin(state, self.put_request(), clock=clock())
        self.assertEqual(pending.status, "pending")
        self.assertEqual(plan.action, "PutImage")

    def test_request_scope_and_independent_image_snapshots_cannot_be_substituted(self):
        state = self.initial()
        for target in (protocol.Scope(registry_id="999999999999", region=REGION, repository_name=REPOSITORY),
                protocol.Scope(registry_id=REGISTRY, region="us-west-2", repository_name=REPOSITORY),
                protocol.Scope(registry_id=REGISTRY, region=REGION, repository_name="other-repository")):
            self.refuse(lambda: planner.begin(state, request("InitiateLayerUpload", target=target), clock=clock()))
        other, _ = image_fixture(config=b"other-config", layers=(b"other-layer",))
        other_state = self.initial(image=other)
        self.refuse(lambda: planner.begin(other_state, request("BatchCheckLayerAvailability",
            layerDigests=[self.image.config.digest]), clock=clock()))
        parsed = request("InitiateLayerUpload")
        pending, plan = planner.begin(state, parsed, clock=clock())
        different_pending, _ = planner.begin(other_state, parsed, clock=clock())
        self.refuse(lambda: planner.apply_response(different_pending, plan,
            response(parsed, uploadId=UPLOAD_ID, partSize=PART_SIZE), clock=clock()))
        changed_scope_pending, _ = planner.begin(self.initial(selected_scope=scope(credential_generation=8)),
            parsed, clock=clock())
        self.refuse(lambda: planner.apply_response(changed_scope_pending, plan,
            response(parsed, uploadId=UPLOAD_ID, partSize=PART_SIZE), clock=clock()))
        self.assertEqual(pending.artifact_sha256, self.image.commitment_sha256)

    def test_original_dual_clock_deadline_and_rollback_guards_remain(self):
        initial = self.initial(lifetime=10)
        parsed = request("BatchCheckLayerAvailability", layerDigests=[self.image.config.digest])
        pending, plan = planner.begin(initial, parsed, clock=clock(2))
        acknowledged = availability(parsed, {self.image.config.digest}, self.blobs)
        for observed in (clock(10), clock(9, 10_000_000_000), clock(10, 9_000_000_000),
                clock(1, 3_000_000_000), clock(3, 1_000_000_000)):
            self.refuse(lambda: planner.apply_response(pending, plan, acknowledged, clock=observed))
        active = planner.apply_response(pending, plan, acknowledged, clock=clock(3))
        self.assertEqual(active.deadline, initial.deadline)
        self.assertEqual(active.clock, clock(3))
        for observed in (clock(10), clock(9, 10_000_000_000), clock(2), clock(4, 2_000_000_000)):
            self.refuse(lambda: planner.begin(active, request("InitiateLayerUpload"), clock=observed))
        self.refuse(lambda: planner.begin(active, request("InitiateLayerUpload"),
            clock=planner.Clock(unix_seconds=True, monotonic_ns=MONO)))
        self.refuse(lambda: planner.begin(active, request("InitiateLayerUpload"), clock=object()))

    def test_failure_is_terminal_uncertainty_for_writes_and_failed_for_reads(self):
        for action, expected in (("InitiateLayerUpload", "uncertain"), ("BatchCheckLayerAvailability", "failed")):
            parsed = request(action, **({"layerDigests": [self.image.config.digest]}
                if action == "BatchCheckLayerAvailability" else {}))
            initial = self.initial(lifetime=5)
            pending, plan = planner.begin(initial, parsed, clock=clock(2))
            for observed in (clock(20), clock(1), clock(3, 1_000_000_000)):
                terminal = planner.fail(pending, plan, clock=observed)
                self.assertEqual(terminal.status, expected)
                self.assertEqual(terminal.deadline, initial.deadline)
                self.assertEqual(terminal.calls, pending.calls)
                self.assertEqual(terminal.part_bytes, pending.part_bytes)
                self.assertEqual(terminal.clock, observed if observed == clock(20) else pending.clock)
                self.refuse(lambda: planner.begin(terminal, parsed, clock=clock(3)))
                self.refuse(lambda: planner.fail(terminal, plan, clock=clock(3)))
            self.refuse(lambda: planner.fail(pending, plan, clock=object()))
            self.refuse(lambda: planner.fail(pending, plan,
                clock=planner.Clock(unix_seconds=NOW, monotonic_ns=-1)))

    def test_bad_ack_never_advances_offset_and_failure_cannot_resume(self):
        state = self.initiate(self.initial())
        parsed = self.part_request(CONFIG)
        pending, plan = planner.begin(state, parsed, clock=clock(), read_blob=self.read_blob)
        self.assertEqual(pending.upload.acknowledged_offset, 0)
        for wrong in ({"lastByteReceived": len(CONFIG)}, {"repositoryName": "different-repository"},
                {"uploadId": "00000000-0000-4000-8000-000000000009"}):
            with self.assertRaises(protocol.ProtocolError):
                response(parsed, **{"registryId": REGISTRY, "repositoryName": REPOSITORY,
                    "uploadId": UPLOAD_ID, "lastByteReceived": len(CONFIG) - 1, **wrong})
        stopped = planner.fail(pending, plan, clock=clock())
        self.assertEqual(stopped.status, "uncertain")
        self.assertEqual(stopped.upload.acknowledged_offset, 0)
        self.assertEqual(stopped.part_bytes, len(CONFIG))  # Reservation stays charged.
        self.refuse(lambda: planner.begin(stopped, parsed, clock=clock(), read_blob=self.read_blob))
        good = response(parsed, registryId=REGISTRY, repositoryName=REPOSITORY,
            uploadId=UPLOAD_ID, lastByteReceived=len(CONFIG) - 1)
        self.refuse(lambda: planner.apply_response(stopped, plan, good, clock=clock()))

    def test_comparison_and_call_budgets_bound_work_without_partial_mutation(self):
        initial = self.initial()
        first = self.mark_available(initial, [self.image.config.digest])
        with patch.object(planner, "MAX_CALLS", 1):
            self.refuse(lambda: planner.begin(first, request("InitiateLayerUpload"), clock=clock()))
        state = self.initiate(first)
        parsed = self.part_request(PREFIX)
        for name, limit in (("MAX_COMPARISON_BYTES", MIB), ("MAX_COMPARISON_CALLS", 1)):
            reads = []

            def observed(key, offset, length):
                reads.append((key, offset, length))
                return self.read_blob(key, offset, length)

            with patch.object(planner, name, limit):
                self.refuse(lambda: planner.begin(state, parsed, clock=clock(), read_blob=observed))
            self.assertEqual(len(reads), 1)
            self.assertEqual(sum(row[2] for row in reads), MIB)
            self.assertEqual((state.comparison_bytes, state.comparison_calls, state.part_bytes), (0, 0, 0))
            self.assertEqual(state.upload.acknowledged_offset, 0)
        pending, _ = planner.begin(state, parsed, clock=clock(), read_blob=self.read_blob)
        self.assertEqual(pending.part_bytes, len(PREFIX))
        self.assertEqual((pending.comparison_bytes, pending.comparison_calls), (2 * len(PREFIX), 4))

    def test_unchanged_reader_exact_bytes_bounded_reads_and_cancel_controls(self):
        state = self.initiate(self.initial())
        parsed = self.part_request(CONFIG)
        for reader in (None, lambda *_: b"", lambda *_: "PRIVATE-CANARY",
                lambda *_: bytearray(CONFIG), lambda *_: CONFIG + b"!"):
            self.refuse(lambda: planner.begin(state, parsed, clock=clock(), read_blob=reader))
        self.refuse(lambda: planner.begin(state, self.part_request(b"x" * len(CONFIG)),
            clock=clock(), read_blob=self.read_blob))

        def unavailable(*_):
            raise OSError("PRIVATE-CANARY")

        self.refuse(lambda: planner.begin(state, parsed, clock=clock(), read_blob=unavailable))

        class Cancel(BaseException):
            pass

        def cancelled(*_):
            raise Cancel()

        with self.assertRaises(Cancel):
            planner.begin(state, parsed, clock=clock(), read_blob=cancelled)
        self.assertEqual(state.upload.acknowledged_offset, 0)
        self.assertEqual((state.part_bytes, state.comparison_calls), (0, 0))
        pending, plan = planner.begin(state, parsed, clock=clock(), read_blob=self.read_blob)
        self.assertEqual(pending.part_bytes, len(CONFIG))
        self.assertEqual(plan.request.part_bytes, CONFIG)

    def test_completed_upload_id_cannot_be_reused_for_another_blob(self):
        state = self.complete(self.part(self.initiate(self.initial()), CONFIG), self.image.config.digest)
        self.assertIn(UPLOAD_ID, state.seen_upload_ids)
        self.assertIsNone(state.upload)
        parsed = request("InitiateLayerUpload")
        pending, plan = planner.begin(state, parsed, clock=clock())
        self.refuse(lambda: planner.apply_response(pending, plan,
            response(parsed, uploadId=UPLOAD_ID, partSize=PART_SIZE), clock=clock()))
        stopped = planner.fail(pending, plan, clock=clock())
        self.assertEqual(stopped.status, "uncertain")
        self.assertEqual(stopped.seen_upload_ids, state.seen_upload_ids)

    def test_optional_response_media_is_joined_to_verified_artifact(self):
        key = self.image.config.digest
        parsed = request("BatchCheckLayerAvailability", layerDigests=[key])
        pending, plan = planner.begin(self.initial(), parsed, clock=clock())
        wrong = response(parsed, layers=[{"layerDigest": key, "layerAvailability": "AVAILABLE",
            "layerSize": len(CONFIG), "mediaType": artifact.DOCKER_CONFIG}], failures=[])
        self.refuse(lambda: planner.apply_response(pending, plan, wrong, clock=clock()))
        right = response(parsed, layers=[{"layerDigest": key, "layerAvailability": "AVAILABLE",
            "mediaType": artifact.OCI_CONFIG}], failures=[])
        self.assertIn(key, planner.apply_response(pending, plan, right, clock=clock()).ready_digests)
        ready = self.mark_available(self.initial(), sorted(self.blobs))
        omitted_media = request("PutImage", imageManifest=self.image.manifest_bytes.decode(),
            imageTag="fixture-tag", imageDigest=self.image.manifest.digest)
        pending, plan = planner.begin(ready, omitted_media, clock=clock())
        image_response = {"registryId": REGISTRY, "repositoryName": REPOSITORY,
            "imageId": {"imageDigest": self.image.manifest.digest, "imageTag": "fixture-tag"},
            "imageManifest": self.image.manifest_bytes.decode()}
        wrong = response(omitted_media, image={**image_response, "imageManifestMediaType": artifact.DOCKER_MANIFEST})
        self.refuse(lambda: planner.apply_response(pending, plan, wrong, clock=clock()))
        for extra in ({}, {"imageManifestMediaType": artifact.OCI_MANIFEST}):
            result = planner.apply_response(pending, plan, response(omitted_media,
                image={**image_response, **extra}), clock=clock())
            self.assertEqual(result.status, "published")


if __name__ == "__main__":
    unittest.main(verbosity=2)
