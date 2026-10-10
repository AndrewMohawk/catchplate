#!/usr/bin/env python3
"""Closed diagnostic and scheduling controls; not storage/deployment acceptance.

The registered API, administrator/Origin/input checks, bounded worker, middleware
and outer ASGI sender are real. Profile selection, administrator token source,
catalog persistence and outbox work are synthetic; storage callback marks prove
context propagation, not a real transaction, publication or durable commit.
No service/socket, provider request or application lifespan is started.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import operator_catalog_timing as timing

CANARY = "synthetic-secret-canary https://private.invalid/?token=secret"
TOKEN = "synthetic-catalog-timing-admin-token"
ACTOR = "synthetic-catalog-timing-actor"
ORIGIN = "https://synthetic.invalid"
PATH = "/api/operator-demo/credentials"
SCOPE_KEY = "serverware.operator_catalog_timing"
BODY = json.dumps({"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
    "name": CANARY, "auth_type": "bearer", "secret": CANARY}).encode()
OPERATIONS = frozenset({
    "create_credential", "revoke_credential", "create_github_credential",
    "replace_credential_key", "create_npm_credential", "create_application",
    "revoke_application", "rotate_application_token", "set_application_proxy_authentication",
    "create_rule", "revoke_rule", "create_gmail_rule", "create_github_rule",
    "create_npm_rule", "create_npm_publish_rule",
})
STORAGE_MARKS = ("publication_wait", "publication_acquired", "sqlite_open", "sqlite_begin",
    "bindings_validated", "change_done", "policy_published", "audit_appended",
    "commit_started", "commit_done", "materialize_started", "materialize_done",
    "publication_released", "receipt_ready")
LABELS = ("api_admitted", "payload_validated", "mutation_queued", "mutation_slot",
    "mutation_worker", *STORAGE_MARKS, "mutation_done", "outbox_queued", "outbox_slot",
    "outbox_worker", "outbox_done", "response_ready", "response_sent")


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
    test.assertLessEqual(len(line.encode("ascii")), 4096)
    test.assertEqual(line.count("\n"), 1)
    test.assertTrue(line.endswith("\n"))
    value = json.loads(line)
    test.assertEqual(set(value), {"schema", "ordinal", "operation", "outcome", "elapsed_ms", "marks"})
    test.assertEqual(value["schema"], "serverware.operatorCatalogTiming/v1")
    test.assertIn(value["operation"], OPERATIONS)
    test.assertIs(type(value["ordinal"]), int)
    test.assertTrue(1 <= value["ordinal"] <= 64)
    test.assertIn(value["outcome"], {"complete", "failed", "cancelled"})
    for elapsed in [value["elapsed_ms"], *value["marks"].values()]:
        test.assertIs(type(elapsed), int)
        test.assertTrue(0 <= elapsed <= (1 << 63) - 1)
    test.assertLessEqual(set(value["marks"]), set(LABELS))
    for forbidden in (CANARY, TOKEN, ACTOR, "private.invalid", "Authorization", "expected_revision", "secret"):
        test.assertNotIn(forbidden, line)
    return value


class CatalogTimingTests(unittest.TestCase):
    def setUp(self):
        self.stack = observations(self)

    def test_closed_profile_operation_labels_activation_and_first_marks(self):
        class String(str):
            pass
        self.assertEqual(timing._OPERATIONS, OPERATIONS)
        self.assertEqual(timing._LABELS, frozenset(LABELS))
        self.assertEqual((timing._LIMIT, timing._MAX_LINE_BYTES), (64, 4096))
        for gate in (False, None, 1, "true", object()):
            self.assertIsNone(timing.create("create_credential", operator_development=gate))
        for operation in (CANARY, "create_credential\n", String("create_credential"), [], None, "x" * 65):
            self.assertIsNone(timing.create(operation, operator_development=True))
        for operation in OPERATIONS:
            self.assertIs(type(timing.create(operation, operator_development=True)), timing.CatalogTiming)
        tracker = timing.create("create_credential", operator_development=True)
        for label in LABELS:
            timing.mark(tracker, label)
            timing.mark(tracker, label)
        for label in (CANARY, [], String("response_sent"), None):
            timing.mark(tracker, label)
        self.assertEqual(self.lines, [])
        timing.activate(tracker)
        timing.finish(tracker, "complete")
        value = record(self, self.lines[0])
        self.assertEqual(value["marks"], {label: index + 1 for index, label in enumerate(LABELS)})
        self.assertEqual(value["elapsed_ms"], len(LABELS) + 1)

    def test_clock_bounds_line_bound_and_failed_sink_spend_only_one_budget(self):
        for now, expected in ((-1, 0), (1 << 100, (1 << 63) - 1)):
            with patch.object(timing, "_clock_ns", return_value=0):
                tracker = timing.create("create_rule", operator_development=True)
            timing.activate(tracker)
            with patch.object(timing, "_clock_ns", return_value=now):
                timing.mark(tracker, "mutation_done")
                timing.finish(tracker, "complete")
            self.assertEqual(record(self, self.lines[-1])["elapsed_ms"], expected)
        for boundary in (patch.object(timing, "_MAX_LINE_BYTES", 1),
                patch.object(timing, "_write_record", side_effect=OSError(CANARY))):
            tracker = timing.create("create_rule", operator_development=True)
            timing.activate(tracker)
            before = timing._count
            with boundary:
                timing.finish(tracker, "complete")
            timing.finish(tracker, "complete")
            self.assertEqual(timing._count, before + 1)
        self.assertEqual(len(self.lines), 2)

    def test_clock_and_lock_failures_do_not_replace_original_result_or_error(self):
        with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
            self.assertIsNone(timing.create("create_rule", operator_development=True))
        class BrokenLock:
            def acquire(self, **kwargs):
                raise OSError(CANARY)
        failure, sentinel = RuntimeError(CANARY), object()
        for broken_clock in (False, True):
            tracker = timing.create("create_rule", operator_development=True)
            timing.activate(tracker)
            with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)) if broken_clock else ExitStack():
                if not broken_clock:
                    tracker._lock = BrokenLock()
                timing.mark(tracker, "mutation_done")
                timing.activate(tracker)
                with self.assertRaises(RuntimeError) as caught:
                    try:
                        raise failure
                    finally:
                        timing.finish(tracker, "failed")
                self.assertIs(caught.exception, failure)
            timing.finish(tracker, "complete")
        tracker = timing.create("create_rule", operator_development=True)
        timing.activate(tracker)
        with patch.object(timing, "_limit_lock", BrokenLock()):
            def operation():
                try:
                    return sentinel
                finally:
                    timing.finish(tracker, "complete")
            self.assertIs(operation(), sentinel)
        timing.finish(tracker, "complete")
        self.assertEqual(self.lines, [])

    def test_terminal_cancellation_cannot_upgrade_under_contention(self):
        for activated in (False, True):
            tracker = timing.create("create_rule", operator_development=True)
            if activated:
                timing.activate(tracker)
            with tracker._lock:
                timing.finish(tracker, "cancelled")
            timing.activate(tracker)
            timing.mark(tracker, "response_sent")
            timing.finish(tracker, "complete")
        tracker = timing.create("create_rule", operator_development=True)
        timing.finish(tracker, "failed")
        timing.activate(tracker)
        timing.finish(tracker, "complete")
        self.assertEqual(self.lines, [])
        tracker = timing.create("create_rule", operator_development=True)
        timing.activate(tracker)
        timing.finish(tracker, CANARY)
        timing.finish(tracker, [])
        timing.finish(tracker, "cancelled")
        timing.mark(tracker, "response_sent")
        timing.finish(tracker, "complete")
        self.assertEqual(record(self, self.lines[0])["outcome"], "cancelled")
        self.assertEqual(record(self, self.lines[0])["marks"], {})
        tracker = timing.create("create_rule", operator_development=True)
        timing.activate(tracker)
        with timing._limit_lock:
            timing.finish(tracker, "complete")
        timing.finish(tracker, "complete")
        self.assertEqual(len(self.lines), 1)

    def test_process_budget_is_exact_and_concurrently_bounded(self):
        def complete():
            tracker = timing.create("create_rule", operator_development=True)
            timing.activate(tracker)
            timing.finish(tracker, "complete")
            timing.finish(tracker, "complete")
        for _ in range(96):
            complete()
        self.assertEqual((len(self.lines), timing._count), (64, 64))
        self.assertEqual({record(self, line)["ordinal"] for line in self.lines}, set(range(1, 65)))
        self.lines.clear()
        with timing._limit_lock:
            timing._count = 0
        barrier, failures = threading.Barrier(8, timeout=3), []
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
        for _ in range(64):
            complete()
        self.assertEqual({record(self, line)["ordinal"] for line in self.lines}, set(range(1, 65)))

    def test_context_binding_resets_and_preserves_body_exceptions(self):
        tracker = timing.create("create_rule", operator_development=True)
        failure = RuntimeError(CANARY)
        self.assertIsNone(timing.current())
        with timing.bind(tracker):
            self.assertIs(timing.current(), tracker)
            with self.assertRaises(RuntimeError) as caught:
                with timing.bind(None):
                    self.assertIsNone(timing.current())
                    raise failure
            self.assertIs(caught.exception, failure)
            self.assertIs(timing.current(), tracker)
        self.assertIsNone(timing.current())
        for invalid in (None, object(), CANARY):
            with timing.bind(invalid):
                self.assertIsNone(timing.current())
            timing.mark(invalid, CANARY)
            timing.activate(invalid)
            timing.finish(invalid, "failed")
        self.assertEqual(self.lines, [])


class CatalogTimingWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from serverware import app
        self.app = app
        self.stack = observations(self)

    async def test_real_bounded_worker_cancellation_keeps_slot_and_context(self):
        slots = asyncio.BoundedSemaphore(1)
        tracker = timing.create("create_rule", operator_development=True)
        timing.activate(tracker)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        seen = []
        def worker():
            seen.append(timing.current())
            entered.set()
            try:
                if not release.wait(3):
                    raise AssertionError("synthetic worker was not released")
                timing.mark(timing.current(), "commit_done")
                return "synthetic-result"
            finally:
                finished.set()
        task = asyncio.create_task(self.app._run_bounded_blocking(slots, worker,
            _catalog_observation=tracker, _catalog_phase="mutation"))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            timing.finish(tracker, "cancelled")
            self.assertEqual(slots._value, 0)
            self.assertFalse(finished.is_set())
            self.assertIsNone(timing.current())
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            if entered.is_set():
                self.assertTrue(await asyncio.to_thread(finished.wait, 2))
                await asyncio.wait_for(slots.acquire(), 2)
                slots.release()
        timing.finish(tracker, "complete")
        self.assertEqual(seen, [tracker])
        self.assertEqual(slots._value, 1)
        self.assertEqual(len(self.lines), 1)
        value = record(self, self.lines[0])
        self.assertEqual(value["outcome"], "cancelled")
        self.assertEqual(set(value["marks"]), {"mutation_queued", "mutation_slot", "mutation_worker"})

    async def test_real_worker_original_error_invalid_phase_and_context_reset(self):
        slots = asyncio.BoundedSemaphore(1)
        tracker = timing.create("create_rule", operator_development=True)
        timing.activate(tracker)
        failure = RuntimeError(CANARY)
        def worker():
            self.assertIs(timing.current(), tracker)
            raise failure
        with self.assertRaises(RuntimeError) as caught:
            await self.app._run_bounded_blocking(slots, worker,
                _catalog_observation=tracker, _catalog_phase="mutation")
        self.assertIs(caught.exception, failure)
        self.assertEqual(slots._value, 1)
        self.assertIsNone(timing.current())
        self.assertIsNone(await self.app._run_bounded_blocking(slots, timing.current,
            _catalog_observation=tracker, _catalog_phase=CANARY))
        timing.finish(tracker, "failed")
        self.assertEqual(set(record(self, self.lines[0])["marks"]),
            {"mutation_queued", "mutation_slot", "mutation_worker", "mutation_done"})


class CatalogTimingASGITests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from serverware import app, auth, development_sandbox, operator_demo
        from serverware import operator_catalog_api as api, operator_catalog_inputs as inputs
        from serverware import operator_catalog_mutations as mutations
        self.app, self.auth, self.owner, self.api, self.mutations = app, auth, operator_demo, api, mutations
        self.stack = observations(self)
        self.stored, self.drains, self.trackers = [], [], []
        self.receipt = {"syntheticReceipt": CANARY}
        for owner, name, value in ((operator_demo, "active", lambda: True),
                (development_sandbox, "active", lambda: False),
                (auth, "admin_token", lambda: TOKEN), (auth, "ADMIN_USER_ID", ACTOR),
                (auth, "ADMIN_ROLES", ("admin",)), (api.config, "PUBLIC_URL", ORIGIN),
                (api, "_WORKER_SLOTS", asyncio.BoundedSemaphore(4)),
                (app, "_METADATA_AUDIT_OUTBOX_DRAIN_SLOTS", asyncio.BoundedSemaphore(1)),
                (app, "_SIGNED_RESPONSE_BUFFER_SLOTS", asyncio.BoundedSemaphore(16))):
            self.stack.enter_context(patch.object(owner, name, value))
        def store(payload, actor):
            self.assertIs(type(payload), inputs.CredentialInput)
            self.assertEqual((payload.secret, actor), (CANARY, ACTOR))
            tracker = timing.current()
            self.trackers.append(tracker)
            self.stored.append((payload, actor))
            # Synthetic storage stages: only observation propagation is tested.
            for label in STORAGE_MARKS:
                timing.mark(tracker, label)
            return dict(self.receipt)
        def drain(**kwargs):
            self.drains.append((kwargs, timing.current()))
            return {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
        self.stack.enter_context(patch.object(mutations, "create_credential", store))
        self.stack.enter_context(patch.object(mutations, "catalog_status", return_value={"syntheticCatalog": True}))
        self.stack.enter_context(patch.object(app.db, "drain_metadata_audit_outbox", drain))

    async def request(self, *, path=PATH, method="POST", body=BODY, token=TOKEN,
            origin=ORIGIN, query=b"", content_type="application/json", messages=None, send_error=None):
        messages = [] if messages is None else messages
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "scheme": "https", "method": method, "path": path, "raw_path": path.encode(),
            "root_path": "", "query_string": query, "server": ("synthetic.invalid", 443),
            "client": ("127.0.0.1", 30001), "headers": [(b"host", b"synthetic.invalid"),
                (b"content-type", content_type.encode()), (b"content-length", str(len(body)).encode()),
                (b"x-serverware-admin-token", token.encode()), (b"origin", origin.encode())]}
        received, complete = False, asyncio.Event()
        async def receive():
            nonlocal received
            if not received:
                received = True
                return {"type": "http.request", "body": body, "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            if send_error is not None:
                raise send_error
            messages.append(dict(message))
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                complete.set()
        try:
            await asyncio.wait_for(self.app.app(scope, receive, send), 5)
        finally:
            complete.set()
            self.assertNotIn(SCOPE_KEY, scope)
        return messages

    def response(self, messages):
        starts = [item for item in messages if item["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        headers = {name.lower(): value for name, value in starts[0]["headers"]}
        self.assertEqual(headers[b"cache-control"], b"no-store")
        body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
        self.assertNotIn(b"operatorCatalogTiming", body)
        return starts[0]["status"], json.loads(body)

    async def test_actual_api_middleware_sender_exact_response_context_and_marks(self):
        traced = await self.request()
        self.assertEqual(self.response(traced), (201, self.receipt))
        self.assertEqual(len(self.lines), 1)
        value = record(self, self.lines[0])
        self.assertEqual(value["outcome"], "complete")
        self.assertEqual(set(value["marks"]), set(LABELS))
        self.assertEqual([value["marks"][label] for label in LABELS], sorted(value["marks"].values()))
        self.assertIs(type(self.trackers[0]), timing.CatalogTiming)
        self.assertEqual(self.drains, [({"limit": 100}, self.trackers[0])])
        self.assertIsNone(timing.current())
        with patch.object(timing, "create", return_value=None):
            baseline = await self.request()
        self.assertEqual(traced, baseline)
        with patch.object(timing, "_write_record", side_effect=OSError(CANARY)):
            self.assertEqual(await self.request(), baseline)
        with patch.object(timing, "_clock_ns", side_effect=OSError(CANARY)):
            self.assertEqual(await self.request(), baseline)
        self.assertEqual(len(self.lines), 1)

    async def test_rejected_admission_input_and_unrelated_get_emit_nothing(self):
        for kwargs, expected in (({"token": "wrong"}, 401), ({"origin": "https://wrong.invalid"}, 403),
                ({"query": b"unexpected=1"}, 422), ({"body": b"{}"}, 422),
                ({"body": b"{"}, 422), ({"content_type": "text/plain"}, 415)):
            self.assertEqual(self.response(await self.request(**kwargs))[0], expected)
        with patch.object(self.auth, "ADMIN_ROLES", ("viewer",)):
            self.assertEqual(self.response(await self.request())[0], 403)
        with patch.object(self.owner, "active", return_value=False), \
                patch.object(timing, "create", side_effect=AssertionError("excluded tracker")):
            self.assertEqual(self.response(await self.request())[0], 404)
        with patch.object(timing, "create", side_effect=AssertionError("unrelated tracker")):
            self.assertEqual(self.response(await self.request(path="/api/operator-demo/catalog", method="GET", body=b"")),
                (200, {"syntheticCatalog": True}))
        self.assertEqual(self.stored, [])
        self.assertEqual(self.lines, [])
        self.assertEqual(timing._count, 0)

    async def test_handled_mutation_error_is_response_complete_not_commit_proof(self):
        with patch.object(self.mutations, "create_credential", side_effect=RuntimeError(CANARY)):
            status, body = self.response(await self.request())
        self.assertEqual(status, 503)
        self.assertNotIn(CANARY, json.dumps(body))
        value = record(self, self.lines[0])
        self.assertEqual(value["outcome"], "complete")
        self.assertIn("mutation_done", value["marks"])
        self.assertNotIn("commit_done", value["marks"])
        self.assertNotIn("receipt_ready", value["marks"])
        failure = RuntimeError(CANARY)
        with self.assertRaises(RuntimeError) as caught:
            await self.request(send_error=failure)
        self.assertIs(caught.exception, failure)
        value = record(self, self.lines[1])
        self.assertEqual(value["outcome"], "failed")
        self.assertIn("response_ready", value["marks"])
        self.assertNotIn("response_sent", value["marks"])

    async def test_actual_post_handler_cancellation_retains_outbox_slot_and_terminal(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def drain(**kwargs):
            self.assertIs(timing.current(), self.trackers[0])
            entered.set()
            try:
                if not release.wait(3):
                    raise AssertionError("synthetic outbox was not released")
                return {"claimed": 0, "audited": 0, "failed": 0, "pending": 0}
            finally:
                finished.set()
        messages = []
        slots = self.app._METADATA_AUDIT_OUTBOX_DRAIN_SLOTS
        with patch.object(self.app.db, "drain_metadata_audit_outbox", drain):
            task = asyncio.create_task(self.request(messages=messages))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.assertEqual(len(self.stored), 1)
                self.assertEqual(messages, [])
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertFalse(finished.is_set())
                self.assertEqual(slots._value, 0)
                self.assertEqual(len(self.lines), 1)
                value = record(self, self.lines[0])
                self.assertEqual(value["outcome"], "cancelled")
                self.assertIn("mutation_done", value["marks"])
                self.assertNotIn("outbox_done", value["marks"])
                self.assertNotIn("response_sent", value["marks"])
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
                if entered.is_set():
                    self.assertTrue(await asyncio.to_thread(finished.wait, 2))
                    await asyncio.wait_for(slots.acquire(), 2)
                    slots.release()
        self.assertEqual(slots._value, 1)
        self.assertEqual(messages, [])
        self.assertEqual(len(self.lines), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
