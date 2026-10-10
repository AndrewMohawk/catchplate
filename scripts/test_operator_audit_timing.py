#!/usr/bin/env python3
"""Isolated diagnostic/scheduling tests, not DB or deployment acceptance.

The ASGI tests exercise the registered route, middleware, policy getter/loader
and real Ed25519 signatures. Eligibility, storage, policy I/O/compilation,
signing context and in-memory key sources are synthetic. The loader tests prove
ordering/copy behavior, not policy authentication. No service/socket is started.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import operator_audit_timing as timing

CANARY = "synthetic-secret-canary https://private.invalid/?token=secret"
BODY = (b' {"events":[{"eventId":"sha256:' + b'1' * 64
        + b'","eventType":"data_plane.test","event":{"syntheticOnly":true}}]}\n')
DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()
TOKEN = "synthetic-audit-timing-token"
NONCE = base64.urlsafe_b64encode(bytes([121]) * 32).rstrip(b"=")
LABELS = (
    "audit_queued", "audit_slot", "audit_worker", "audit_admitted", "audit_done",
    "outbox_queued", "outbox_slot", "outbox_worker", "outbox_done",
    "sign_queued", "sign_slot", "sign_worker", "sign_policy_enter",
    "sign_policy_lock_acquired", "sign_policy_done", "sign_manifest_done",
    "sign_artifacts_done", "sign_statement_done", "sign_crypto_done", "response_ready", "response_sent",
)


class Clock:
    def __init__(self):
        self.value, self.lock = 0, threading.Lock()

    def __call__(self):
        with self.lock:
            self.value += 1_000_000
            return self.value


def observations(test):
    stack = ExitStack()
    test.addCleanup(stack.close)
    with timing._limit_lock:
        old_count, timing._count = timing._count, 0
    def restore():
        with timing._limit_lock:
            timing._count = old_count
    stack.callback(restore)
    test.lines = []
    stack.enter_context(patch.object(timing, "_write_record", test.lines.append))
    stack.enter_context(patch.object(timing, "_clock_ns", Clock()))
    return stack


def record(test, line):
    test.assertLess(len(line), 2048)
    test.assertEqual(line.count("\n"), 1)
    test.assertTrue(line.endswith("\n"))
    value = json.loads(line)
    test.assertEqual(set(value), {"schema", "event_count", "batch_digest", "outcome", "elapsed_ms", "marks"})
    test.assertEqual(value["schema"], "serverware.operatorAuditTiming/v1")
    test.assertEqual(value["batch_digest"], DIGEST)
    test.assertIs(type(value["event_count"]), int)
    test.assertTrue(1 <= value["event_count"] <= 200)
    test.assertIn(value["outcome"], {"complete", "failed", "cancelled"})
    test.assertIs(type(value["elapsed_ms"]), int)
    test.assertTrue(0 <= value["elapsed_ms"] <= (1 << 63) - 1)
    test.assertLessEqual(set(value["marks"]), set(LABELS))
    for elapsed in value["marks"].values():
        test.assertIs(type(elapsed), int)
        test.assertTrue(0 <= elapsed <= (1 << 63) - 1)
    for forbidden in (CANARY, "private.invalid", TOKEN, "syntheticOnly", "Authorization", "eventId"):
        test.assertNotIn(forbidden, line)
    return value


class PolicyLookupFixture:
    """Actual getter/loader and copies; synthetic external authority/I/O only."""

    MISS = ["publication", "stat", "trust", "read", "trust", "compile",
            "high_water", "identity", "trust_recheck", "high_water", "publication"]
    HIT = ["publication", "stat", "trust", "high_water", "identity",
           "trust_recheck", "high_water", "publication"]

    def __init__(self, test, stack):
        from serverware import policy_bundle as policy
        self.policy, self.calls = policy, []
        self.path = Path("/synthetic-audit-timing/policy.json")
        self.lock = threading.RLock()
        self.snapshot = policy.PolicySnapshot(
            raw={"synthetic": {"copy": [1]}}, hash="sha256:" + "2" * 64,
            principals={}, credentials={}, routes=(),
        )
        self.identity = policy.PolicyFileIdentity(1, 2, 3, 4, 0o100600, 1, 2, 5, 6, "sha256:" + "4" * 64)
        names = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        file_stat = SimpleNamespace(**dict(zip(names, self.identity.stat_components)))
        self.trust = SimpleNamespace(identity=("synthetic-trust",))
        self.loader = policy.PolicyBundleLoader(self.path)
        for name, value in (("POLICY_BUNDLE_PATH", self.path), ("_SNAPSHOT_CACHE_LOCK", self.lock),
                ("_SNAPSHOT_CACHE", None), ("_POLICY_BUNDLE_LOADER", self.loader)):
            stack.enter_context(patch.object(policy, name, value))
        def observed(label, result):
            def call(*args, **kwargs):
                test.assertTrue(self.lock._is_owned(), label)
                self.calls.append(label)
                return result
            return call
        for name, label, result in (
                ("_require_policy_file_publication_settled", "publication", None),
                ("_read_secure_file_stat", "stat", file_stat),
                ("_load_policy_signing_trust", "trust", self.trust),
                ("_read_stable_policy_file", "read", (b"{}", self.identity)),
                ("verify_policy_high_water", "high_water", {}),
                ("_recheck_policy_path_identity", "identity", None),
                ("_recheck_policy_signing_trust", "trust_recheck", None)):
            stack.enter_context(patch.object(policy, name, observed(label, result)))
        def compile_bundle(raw, **kwargs):
            test.assertTrue(self.lock._is_owned())
            test.assertEqual(raw, {})
            test.assertEqual(kwargs, {"verify_signature": True, "validate_schema": True, "signing_trust": self.trust})
            self.calls.append("compile")
            return self.snapshot
        stack.enter_context(patch.object(policy, "compile_policy_bundle", compile_bundle))


class AuditTimingTests(unittest.TestCase):
    def setUp(self):
        observations(self)

    def test_closed_contract_first_marks_and_activation_after_validation(self):
        self.assertEqual(timing._LABELS, frozenset(LABELS))
        self.assertEqual(timing._LIMIT, 64)
        for count, digest in [(False, DIGEST), (1.0, DIGEST), (0, DIGEST), (201, DIGEST),
                (1, CANARY), (1, DIGEST.upper()), (1, DIGEST + "\n"), (1, None)]:
            self.assertIsNone(timing.create(count, digest))
        tracker = timing.create(1, DIGEST)
        for label in LABELS:
            timing.mark(tracker, label)
            timing.mark(tracker, label)
        timing.mark(tracker, CANARY)
        timing.mark(tracker, [])
        self.assertEqual(self.lines, [])
        timing.activate(tracker)
        timing.finish(tracker, "complete")
        value = record(self, self.lines[0])
        self.assertEqual(value["marks"], {label: index + 1 for index, label in enumerate(LABELS)})
        self.assertEqual(value["elapsed_ms"], len(LABELS) + 1)
        self.assertEqual(value["event_count"], 1)
        self.assertEqual(timing._count, 1)

    def test_bad_clock_sink_and_unknown_labels_never_replace_outcome(self):
        with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
            self.assertIsNone(timing.create(1, DIGEST))
        sentinel = object()
        for sink_failure in (False, True):
            tracker = timing.create(1, DIGEST)
            timing.activate(tracker)
            with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
                self.assertIsNone(timing.mark(tracker, "audit_done"))
            with patch.object(timing, "_write_record", side_effect=OSError(CANARY)) if sink_failure else ExitStack():
                def operation():
                    try:
                        return sentinel
                    finally:
                        timing.finish(tracker, "complete")
                self.assertIs(operation(), sentinel)
            timing.finish(tracker, "failed")
        failure = ValueError(CANARY)
        tracker = timing.create(1, DIGEST)
        timing.activate(tracker)
        with patch.object(timing, "_write_record", side_effect=OSError(CANARY)):
            try:
                try:
                    raise failure
                finally:
                    timing.finish(tracker, "failed")
            except ValueError as caught:
                self.assertIs(caught, failure)
        for value in (None, object(), CANARY):
            timing.mark(value, CANARY)
            timing.activate(value)
            timing.finish(value, "failed")
        self.assertEqual(len(self.lines), 1)
        record(self, self.lines[0])

    def test_terminal_latch_cancellation_and_contended_locks_cannot_upgrade(self):
        for activated in (False, True):
            tracker = timing.create(1, DIGEST)
            if activated:
                timing.activate(tracker)
            with tracker._lock:
                timing.finish(tracker, "cancelled")
            timing.activate(tracker)
            timing.mark(tracker, "response_sent")
            timing.finish(tracker, "complete")
        self.assertEqual(self.lines, [])
        tracker = timing.create(1, DIGEST)
        timing.finish(tracker, "failed")
        timing.activate(tracker)
        timing.finish(tracker, "complete")
        self.assertEqual(self.lines, [])
        tracker = timing.create(1, DIGEST)
        timing.activate(tracker)
        timing.finish(tracker, CANARY)
        timing.finish(tracker, [])
        timing.finish(tracker, "cancelled")
        timing.mark(tracker, "response_sent")
        timing.finish(tracker, "complete")
        self.assertEqual(record(self, self.lines[0])["outcome"], "cancelled")
        self.assertEqual(record(self, self.lines[0])["marks"], {})
        tracker = timing.create(1, DIGEST)
        timing.activate(tracker)
        with timing._limit_lock:
            timing.finish(tracker, "complete")
        timing.finish(tracker, "complete")
        self.assertEqual(len(self.lines), 1)

    def test_process_budget_is_exact_and_concurrently_bounded(self):
        def complete():
            tracker = timing.create(1, DIGEST)
            timing.activate(tracker)
            timing.finish(tracker, "complete")
            timing.finish(tracker, "complete")
        for _ in range(96):
            complete()
        self.assertEqual((len(self.lines), timing._count), (64, 64))
        for line in self.lines:
            record(self, line)
        self.lines.clear()
        with timing._limit_lock:
            timing._count = 0
        barrier = threading.Barrier(8, timeout=3)
        failures = []
        def worker():
            try:
                barrier.wait()
                for _ in range(32):
                    complete()
            except BaseException as error:
                failures.append(type(error).__name__)
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(4)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(self.lines), timing._count)
        self.assertLessEqual(timing._count, 64)
        # Contention may drop observations, not exceed the process budget.
        for _ in range(64):
            complete()
        self.assertEqual((len(self.lines), timing._count), (64, 64))


class AuditTimingPolicyLookupTests(unittest.TestCase):
    def setUp(self):
        self.stack = observations(self)
        self.fixture = PolicyLookupFixture(self, self.stack)

    def test_actual_getter_distinguishes_lock_wait_from_loader_work(self):
        fixture = self.fixture
        tracker = timing.create(1, DIGEST)
        timing.activate(tracker)
        entered, reading, release_read = threading.Event(), threading.Event(), threading.Event()
        results, failures = [], []
        original_mark, original_read = timing.mark, fixture.policy._read_stable_policy_file
        def mark(observation, label):
            original_mark(observation, label)
            if observation is tracker and label == "sign_policy_enter":
                entered.set()
        def read(path):
            reading.set()
            if not release_read.wait(3):
                raise AssertionError("synthetic policy read was not released")
            return original_read(path)
        def lookup():
            try:
                results.append(fixture.policy.get_policy_snapshot(_audit_observation=tracker))
                timing.mark(tracker, "sign_policy_done")
                timing.finish(tracker, "complete")
            except BaseException as error:
                failures.append(error)
        worker = threading.Thread(target=lookup)
        with patch.object(timing, "mark", mark), patch.object(fixture.policy, "_read_stable_policy_file", read):
            try:
                with fixture.lock:
                    worker.start()
                    self.assertTrue(entered.wait(3))
                    self.assertFalse(reading.is_set())
                    self.assertEqual(fixture.calls, [])
                    self.assertEqual(tracker._marks, {"sign_policy_enter": 1})
                    self.assertEqual(results, [])
                    with timing._clock_ns.lock:
                        timing._clock_ns.value = 100_000_000
                self.assertTrue(reading.wait(3))
                self.assertEqual(tracker._marks, {"sign_policy_enter": 1, "sign_policy_lock_acquired": 100})
                self.assertEqual(results, [])
                self.assertEqual(self.lines, [])
                with timing._clock_ns.lock:
                    timing._clock_ns.value = 200_000_000
            finally:
                release_read.set()
                worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].hash, fixture.snapshot.hash)
        self.assertIsNot(results[0], fixture.snapshot)
        self.assertEqual(fixture.calls, fixture.MISS)
        value = record(self, self.lines[0])
        self.assertEqual(value["marks"], {"sign_policy_enter": 1, "sign_policy_lock_acquired": 100, "sign_policy_done": 200})
        self.assertEqual(value["outcome"], "complete")

    def test_actual_loader_cache_order_copies_and_disabled_or_bad_observation(self):
        fixture = self.fixture
        # The ordinary call never even invokes the diagnostic wrapper.
        with patch.object(timing, "mark", side_effect=AssertionError("trace-off mark")):
            first = fixture.policy.get_policy_snapshot()
        self.assertEqual(fixture.calls, fixture.MISS)
        self.assertIs(fixture.policy._SNAPSHOT_CACHE, fixture.loader.cache)
        fixture.calls.clear()
        second = fixture.policy.get_policy_snapshot(_audit_observation=CANARY)
        self.assertEqual(fixture.calls, fixture.HIT)
        self.assertIsNot(first, second)
        self.assertIsNot(first.raw, second.raw)
        self.assertIsNot(first.raw["synthetic"], second.raw["synthetic"])
        with self.assertRaises(TypeError):
            first.raw["synthetic"]["copy"] = CANARY
        self.assertEqual(second.raw["synthetic"]["copy"], [1])
        self.assertEqual(fixture.snapshot.raw, {"synthetic": {"copy": [1]}})
        fixture.calls.clear()
        fixture.policy._SNAPSHOT_CACHE = None
        broken_clock_tracker = timing.create(1, DIGEST)
        with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
            third = fixture.policy.get_policy_snapshot(_audit_observation=broken_clock_tracker)
        self.assertEqual(fixture.calls, fixture.MISS)
        self.assertEqual(third.hash, first.hash)
        self.assertEqual(broken_clock_tracker._marks, {})
        self.assertEqual(self.lines, [])
        with patch.object(fixture.policy, "verify_policy_high_water",
                          side_effect=fixture.policy.PolicyBundleError(CANARY)):
            self.assertIsNone(fixture.policy.get_policy_snapshot(_audit_observation=broken_clock_tracker))
        self.assertIsNone(fixture.loader.cache)
        self.assertIsNone(fixture.policy._SNAPSHOT_CACHE)
        # An unrelated loader failure is propagated as the exact original object.
        failure = RuntimeError(CANARY)
        tracker = timing.create(1, DIGEST)
        timing.activate(tracker)
        with patch.object(fixture.loader, "load", side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                fixture.policy.get_policy_snapshot(_audit_observation=tracker)
        self.assertIs(caught.exception, failure)
        timing.finish(tracker, "failed")
        self.assertEqual(record(self, self.lines[0])["marks"].keys(),
                         {"sign_policy_enter", "sign_policy_lock_acquired"})


class AuditTimingASGITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Same isolated app-import boundary as test_legacy_audit_scheduling.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from serverware import app, operator_demo, response_identity, control_plane_data_plane_audit
        self.app, self.identity, self.owner, self.measured = app, response_identity, operator_demo, control_plane_data_plane_audit
        self.stack = observations(self)
        self.stored, self.drains = [], []
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([113]) * 32)
        public = self.key.public_key()
        key_id = "sha256:" + hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        key_info = {"spki_sha256": key_id, "pem": public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
        for name, count in (("_DATA_PLANE_AUDIT_INGEST_SLOTS", 4), ("_METADATA_AUDIT_OUTBOX_DRAIN_SLOTS", 1),
                ("_SIGNED_RESPONSE_WORKER_SLOTS", 4), ("_SIGNED_RESPONSE_BUFFER_SLOTS", 16)):
            self.stack.enter_context(patch.object(app, name, asyncio.BoundedSemaphore(count)))
        self.stack.enter_context(patch.object(operator_demo, "active", return_value=True))
        self.stack.enter_context(patch.object(control_plane_data_plane_audit, "selected", return_value=False))
        self.stack.enter_context(patch.object(app, "DATA_PLANE_AUDIT_INGEST_TOKEN", TOKEN))
        self.stack.enter_context(patch.object(app, "DATA_PLANE_INSTANCE_ID", "synthetic-timing-instance"))
        self.stack.enter_context(patch.object(app, "RELEASE_CHANNEL", "dev"))
        self.policy_fixture = PolicyLookupFixture(self, self.stack)
        self.policy_lookup = self.stack.enter_context(patch.object(
            app, "get_policy_snapshot", wraps=self.policy_fixture.policy.get_policy_snapshot))
        self.stack.enter_context(patch.object(app, "runtime_manifest_digest", return_value="sha256:" + "3" * 64))
        self.stack.enter_context(patch.object(app, "attestation_artifact_digests", return_value={
            "provenance_digest": None, "image_signatures_digest": None, "source_tree_digest": None}))
        self.stack.enter_context(patch.object(response_identity, "response_public_key_info", return_value=key_info))
        self.stack.enter_context(patch.object(response_identity, "_load_response_key", return_value=self.key))
        self.stack.enter_context(patch.object(response_identity, "time", SimpleNamespace(time=lambda: 1_800_000_000.25)))
        def store(events, **kwargs):
            self.stored.append((events, kwargs))
            return [{"synthetic": True} for _ in events]
        def drain(**kwargs):
            self.drains.append(kwargs)
            return {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
        self.stack.enter_context(patch.object(app.db, "record_audit_event_batch", store))
        self.stack.enter_context(patch.object(app.db, "drain_metadata_audit_outbox", drain))

    async def request(self, *, body=BODY, token=TOKEN, messages=None):
        messages = [] if messages is None else messages
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "scheme": "https", "method": "POST", "path": "/api/data-plane/audit", "raw_path": b"/api/data-plane/audit",
            "root_path": "", "query_string": b"", "server": ("synthetic.invalid", 443), "client": ("127.0.0.1", 30001),
            "headers": [(b"host", b"synthetic.invalid"), (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()), (b"x-serverware-data-plane-token", token.encode()),
                (b"x-serverware-response-nonce", NONCE)]}
        received, complete = False, asyncio.Event()
        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            messages.append(dict(message))
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                complete.set()
        try:
            await asyncio.wait_for(self.app.app(scope, receive, send), 5)
        finally:
            complete.set()
        self.assertNotIn("serverware.operator_audit_timing", scope)
        return messages

    def verified(self, messages):
        starts = [row for row in messages if row["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        headers = {name.decode().lower(): value.decode() for name, value in starts[0]["headers"]}
        body = b"".join(row.get("body", b"") for row in messages if row["type"] == "http.response.body")
        decode = lambda raw: base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        statement = json.loads(decode(headers["x-serverware-response-statement-b64"]))
        canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.key.public_key().verify(decode(headers["x-serverware-response-signature"].split(":", 1)[1]), canonical)
        self.assertEqual(statement["body_sha256"], "sha256:" + hashlib.sha256(body).hexdigest())
        unsigned = [(name, value) for name, value in starts[0]["headers"] if not name.lower().startswith(b"x-serverware-response-")]
        digest, count = self.identity.response_headers_binding(unsigned)
        self.assertEqual((statement["response_headers_sha256"], statement["response_header_count"]), (digest, count))
        self.assertEqual(statement["request"], {"method": "POST", "path": "/api/data-plane/audit", "query_sha256": "sha256:" + hashlib.sha256(b"").hexdigest()})
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn(b"operatorAuditTiming", body)
        return starts[0]["status"], json.loads(body)

    async def test_actual_route_csrf_and_outer_signer_preserve_exact_ack_and_all_marks(self):
        traced = await self.request()
        self.assertEqual(self.verified(traced), (200, {"apiVersion": "serverware.dataPlaneAuditAck/v1", "ok": True,
            "accepted": 1, "batchDigest": DIGEST, "instanceId": "synthetic-timing-instance"}))
        self.assertEqual(len(self.lines), 1)
        value = record(self, self.lines[0])
        self.assertEqual(value["outcome"], "complete")
        self.assertEqual(set(value["marks"]), set(LABELS))
        self.assertEqual([value["marks"][label] for label in LABELS], sorted(value["marks"].values()))
        self.assertEqual(self.policy_lookup.call_count, 1)
        self.assertEqual(self.policy_lookup.call_args.args, ())
        self.assertEqual(set(self.policy_lookup.call_args.kwargs), {"_audit_observation"})
        self.assertIs(type(self.policy_lookup.call_args.kwargs["_audit_observation"]), timing.AuditTiming)
        self.assertEqual(self.drains, [{"limit": 100}])
        self.assertEqual(self.stored[0][1], {"actor_type": "data-plane", "actor_id": "synthetic-timing-instance",
            "producer_event_ids": ["sha256:" + "1" * 64], "producer_instance_id": "synthetic-timing-instance"})
        with patch.object(timing, "create", return_value=None):
            baseline = await self.request()
        self.policy_lookup.assert_called_with()
        self.assertEqual(traced, baseline)
        with patch.object(timing, "_write_record", side_effect=OSError(CANARY)):
            self.assertEqual(await self.request(), baseline)
        with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
            self.assertEqual(await self.request(), baseline)

    async def test_rejected_auth_batch_and_excluded_owners_never_activate_output(self):
        bad_batch = json.loads(BODY)
        bad_batch["events"][0]["eventType"] = "not_data_plane"
        for kwargs, expected in (({"token": "wrong"}, 401), ({"body": b"{}"}, 422),
                ({"body": json.dumps(bad_batch).encode()}, 400)):
            self.assertEqual(self.verified(await self.request(**kwargs))[0], expected)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.stored, [])
        with patch.object(self.owner, "active", return_value=False), patch.object(timing, "create", side_effect=AssertionError("excluded trace")):
            self.assertEqual(self.verified(await self.request())[0], 200)
        with patch.object(self.measured, "selected", return_value=True), \
                patch.object(self.measured, "intake", AsyncMock(return_value={"syntheticMeasured": True})), \
                patch.object(timing, "create", side_effect=AssertionError("native trace")):
            self.assertEqual(self.verified(await self.request()), (200, {"syntheticMeasured": True}))
        self.assertEqual(self.lines, [])

    async def test_actual_post_handler_cancellation_keeps_shielded_worker_and_terminal_outcome(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def drain(**kwargs):
            entered.set()
            try:
                if not release.wait(3):
                    raise AssertionError("synthetic drain was not released")
                return {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
            finally:
                finished.set()
        messages = []
        with patch.object(self.app.db, "drain_metadata_audit_outbox", drain):
            task = asyncio.create_task(self.request(messages=messages))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.assertEqual(len(self.stored), 1)
                self.assertEqual(messages, [])
                self.assertEqual(self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS._value, 0)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(finished.is_set())
                self.assertEqual(self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS._value, 0)
                self.assertEqual(len(self.lines), 1)
                value = record(self, self.lines[0])
                self.assertEqual(value["outcome"], "cancelled")
                self.assertIn("audit_done", value["marks"])
                self.assertNotIn("response_sent", value["marks"])
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
                if entered.is_set():
                    self.assertTrue(await asyncio.to_thread(finished.wait, 2))
                    await asyncio.wait_for(self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS.acquire(), 2)
                    self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS.release()
            self.assertEqual(len(self.lines), 1)
            self.assertEqual(messages, [])
            self.assertEqual(self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS._value, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
