#!/usr/bin/env python3
"""Deterministic scheduling controls; no live app or database substitutions.

Only this isolated unit-test process replaces its ingester with a blocking
fixture. The real endpoint, parser and bounded-worker helper are exercised;
this is scheduling coverage, not a database/production acceptance claim.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from starlette.requests import Request
from fastapi import HTTPException
from serverware import app as application
from serverware import control_plane_data_plane_audit as measured


BODY = (b' {"events":[{"eventId":"sha256:' + b'1' * 64
        + b'","eventType":"data_plane.test","event":{"syntheticOnly":true}}]}\n')
TOKEN = "isolated-scheduling-unit-token"


def request(body=BODY):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "path": "/api/data-plane/audit",
                    "headers": []}, receive)


class LegacyAuditSchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.slots = asyncio.BoundedSemaphore(4)
        self.slot_patch = patch.object(application, "_DATA_PLANE_AUDIT_INGEST_SLOTS", self.slots)
        self.selected_patch = patch.object(measured, "selected", return_value=False)
        self.slot_patch.start()
        self.selected_patch.start()
        self.addCleanup(self.slot_patch.stop)
        self.addCleanup(self.selected_patch.stop)

    async def test_blocked_ingester_leaves_receive_loop_responsive_and_exact_ack(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        called = []

        def ingest(batch, token):
            called.append((len(batch.events), token, threading.get_ident()))
            entered.set()
            release.wait(1)
            finished.set()
            return {"ok": True, "accepted": len(batch.events)}

        with patch.object(application, "_ingest_data_plane_audit", ingest):
            pending = asyncio.create_task(application.data_plane_audit(request(), TOKEN))
            try:
                await asyncio.wait_for(asyncio.to_thread(entered.wait, .5), 1)
                self.assertTrue(entered.is_set())
                await asyncio.sleep(.01)
                self.assertFalse(finished.is_set(), "synchronous ingest blocked the receive loop")
            finally:
                release.set()
            result = await pending
        self.assertEqual(called[0][:2], (1, TOKEN))
        self.assertNotEqual(called[0][2], threading.get_ident())
        self.assertEqual(result, {"apiVersion": "serverware.dataPlaneAuditAck/v1", "ok": True,
            "accepted": 1, "batchDigest": "sha256:" + hashlib.sha256(BODY).hexdigest(),
            "instanceId": application.DATA_PLANE_INSTANCE_ID})

    async def test_four_worker_bound_survives_request_cancellation(self):
        release, full = threading.Event(), threading.Event()
        lock = threading.Lock()
        started = 0

        def ingest(batch, token):
            nonlocal started
            with lock:
                started += 1
                if started == 4:
                    full.set()
            release.wait(2)
            return {"ok": True, "accepted": 1}

        with patch.object(application, "_ingest_data_plane_audit", ingest):
            tasks = [asyncio.create_task(application.data_plane_audit(request(), TOKEN)) for _ in range(5)]
            try:
                self.assertTrue(await asyncio.to_thread(full.wait, 1))
                self.assertEqual(started, 4)
                tasks[0].cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await tasks[0]
                await asyncio.sleep(.02)
                self.assertEqual(started, 4, "cancelled request released a still-running worker slot")
            finally:
                release.set()
                await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual(started, 5)
        self.assertEqual(self.slots._value, 4)

    async def test_ingester_http_error_is_preserved(self):
        def ingest(batch, token):
            raise HTTPException(status_code=409, detail="synthetic immutable conflict")

        with patch.object(application, "_ingest_data_plane_audit", ingest):
            with self.assertRaises(HTTPException) as caught:
                await application.data_plane_audit(request(), TOKEN)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.slots._value, 4)

    async def test_measured_intake_never_enters_legacy_worker(self):
        result = {"measuredFixture": True}
        intake = AsyncMock(return_value=result)
        with patch.object(measured, "selected", return_value=True), \
                patch.object(measured, "intake", intake), \
                patch.object(application, "_run_bounded_blocking", AsyncMock(side_effect=AssertionError("legacy worker reached"))):
            original = request()
            self.assertIs(await application.data_plane_audit(original, TOKEN), result)
            intake.assert_awaited_once_with(original)

    async def test_malformed_batch_is_rejected_before_worker(self):
        with patch.object(application, "_ingest_data_plane_audit", side_effect=AssertionError("ingester reached")):
            with self.assertRaises(HTTPException) as caught:
                await application.data_plane_audit(request(b'{}'), TOKEN)
        self.assertEqual(caught.exception.status_code, 422)
        self.assertEqual(self.slots._value, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
