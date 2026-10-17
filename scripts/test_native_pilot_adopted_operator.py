#!/usr/bin/env python3
"""Real isolated public-pipe framing only; no pilot, service or custody owner.

Run in the batch's private user/network namespace. Child processes exercise the
actual Channel parser with synthetic data and real pipes; no core is invented,
no owner guard is mocked and no signing or privileged installation occurs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest

import cryptography

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import native_pilot_operator_channel as channel
from catchplate.native_pilot_operator import Operator

CHILD = """
import json, sys, time
sys.path[:0] = json.loads(sys.argv[1])
from catchplate.native_pilot_operator_channel import Channel, OperatorChannelError
owner = Channel.open_adopted() if sys.argv[2] == 'adopted' else Channel.open()
try:
    bounds = {'expires_at_unix_ns': time.time_ns() +
        (300_000_000 if sys.argv[3] == 'expiry' else 8_000_000_000)} if sys.argv[2] == 'adopted' else {}
    reply = owner.exchange('bootstrap-admission', {'synthetic': True},
        deadline_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 8_000_000_000, **bounds)
    if reply != {'syntheticReply': True}: raise SystemExit(9)
except OperatorChannelError:
    raise SystemExit(7)
finally:
    owner.close()
"""


class AdoptedOperatorControls(unittest.TestCase):
    def exchange(self, *, adopted, mutation=None):
        self.assertEqual(os.getresuid(), (0, 0, 0), "run in the private user namespace")
        paths = json.dumps([str(ROOT), str(Path(cryptography.__file__).resolve().parents[1])])
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", CHILD, paths,
            "adopted" if adopted else "legacy", mutation or "valid"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True)
        try:
            deadline = time.monotonic() + 5
            raw = bytearray()
            while not raw.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                ready, _, _ = select.select([child.stdout], [], [], remaining)
                self.assertTrue(ready)
                chunk = os.read(child.stdout.fileno(), 65536)
                self.assertTrue(chunk)
                raw.extend(chunk)
                self.assertLess(len(raw), 4096)
            original = bytes(raw[:-1])
            request = json.loads(original)
            request_api, reply_api = channel.wire_versions(adopted=adopted)
            self.assertEqual(request["apiVersion"], request_api)
            self.assertEqual(request["phase"], "bootstrap-admission")
            self.assertEqual(request["sequence"], 1)
            if adopted:
                self.assertGreater(int(request["expiresAtUnixNanos"]), 0)
            else:
                self.assertNotIn("expiresAtUnixNanos", request)
            if mutation == "expiry":
                # Leave the actual input pipe open and silent. Expiry, not EOF
                # or the later BOOTTIME cap, must terminate the exchange.
                self.assertEqual(child.wait(timeout=2), 7)
                self.assertEqual(child.stdout.read(), b"")
                self.assertEqual(child.stderr.read(), b"")
                return
            reply = {"apiVersion": reply_api, "sequence": 1, "phase": request["phase"],
                "requestSha256": channel.p.sha(original), "inputs": {"syntheticReply": True}}
            if mutation == "cross-profile":
                reply["apiVersion"] = channel.wire_versions(adopted=not adopted)[1]
            elif mutation == "digest":
                reply["requestSha256"] = channel.p.sha(b"another request")
            elif mutation == "sequence":
                reply["sequence"] = 2
            output, errors = child.communicate(channel.p.canonical(reply) + b"\n", timeout=5)
            self.assertEqual(output, b"")
            self.assertEqual(errors, b"")
            self.assertEqual(child.returncode, 0 if mutation is None else 7)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)

    def test_legacy_real_pipe_exchange_stays_v1(self):
        self.exchange(adopted=False)

    def test_adopted_real_pipe_exchange_requires_v2(self):
        self.exchange(adopted=True)

    def test_adopted_reply_cannot_cross_into_legacy(self):
        self.exchange(adopted=False, mutation="cross-profile")

    def test_legacy_reply_cannot_cross_into_adopted(self):
        self.exchange(adopted=True, mutation="cross-profile")

    def test_reply_binds_actual_request_original(self):
        self.exchange(adopted=True, mutation="digest")

    def test_reply_cannot_skip_a_phase(self):
        self.exchange(adopted=True, mutation="sequence")

    def test_original_unix_expiry_bounds_silent_pipe_wait(self):
        self.exchange(adopted=True, mutation="expiry")

    def test_wire_selection_is_explicit_boolean(self):
        for invalid in (None, 1, 0, "adopted", {}):
            with self.assertRaises(ValueError): channel.wire_versions(adopted=invalid)

    def test_adopted_operator_rejects_data_as_core_before_entry(self):
        for invalid in ({"observed": True}, 9, object(), b"core"):
            with self.assertRaises(ValueError):
                Operator.run_adopted(None, received_core=invalid)


if __name__ == "__main__":
    unittest.main()
