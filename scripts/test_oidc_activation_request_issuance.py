#!/usr/bin/env python3
"""Focused codec/clock/source controls, not native issuance acceptance.

No successful policy, vector, pending row or owner DTO is manufactured. Real
Ed25519 validates the request byte codec only. Controlled clock samples exercise
the unchanged source clock guards. Cold resource ordering is source inspected;
no database, Unix listener, root key delivery or worker readiness is simulated.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_oidc_session_activation_request_issuance as source
from catchplate import authority_oidc_session_activation_request_staging_transport as staging
from catchplate import authority_oidc_session_activation_planner_transport as planner_io
from catchplate import oidc_session_activation_request_dynamic_entrypoint as dynamic
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


EPOCH, MONOTONIC = 1_800_000_000_000_000_000, 1_000_000_000
AGE = 1_000_000_000
WINDOW = (EPOCH, MONOTONIC, MONOTONIC, EPOCH + AGE, MONOTONIC + AGE, AGE, 0)


def work():
    return _ValidationWork(QueryReadValidationLimits())


@contextmanager
def clocks(state):
    with patch.object(source.policy.clock.time, "time_ns", side_effect=lambda: EPOCH + state["elapsed"]), \
            patch.object(source.policy.clock.time, "monotonic_ns", side_effect=lambda: MONOTONIC + state["elapsed"]):
        yield


def body(name, function):
    raw = (ROOT / "catchplate" / name).read_text()
    parsed = ast.parse(raw)
    selected = [node for node in ast.walk(parsed)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function]
    if len(selected) != 1:
        raise AssertionError("source control requires one exact function")
    return ast.get_source_segment(raw, selected[0])


class RequestIssuanceControls(unittest.TestCase):
    def test_dynamic_accepted_socket_is_guarded_nonblocking_before_receive(self):
        meter, calls = work(), []
        deadline = time.monotonic_ns() + 1_000_000_000

        def current():
            calls.append(time.monotonic_ns())
            if calls[-1] >= deadline:
                raise ValueError("original component deadline expired")

        # Real kernel descriptors, no owner/peer/authentication success DTO.
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertIsNone(left.gettimeout())
            left.set_inheritable(True)
            planner_io._prepare_dynamic_connection_on_work(left,
                deadline_ns=deadline, work=meter, current=current)
            self.assertEqual(left.gettimeout(), 0.0)
            self.assertFalse(left.get_inheritable())
            self.assertGreaterEqual(len(calls), 6)
            self.assertGreater(meter.metrics.input_bytes, 0)
        finally:
            left.close()
            right.close()
        selected = body("authority_oidc_session_activation_planner_service.py", "_serve_dynamic_connection")
        self.assertLess(selected.index("_prepare_dynamic_connection_on_work"),
            selected.index("_recv_bounded_request_on_work"))
        old = body("authority_oidc_session_activation_planner_service.py", "_serve_connection")
        self.assertNotIn("setblocking", old)

    def test_actual_signature_and_canonical_request_codec_no_policy_verdict(self):
        private = Ed25519PrivateKey.from_private_bytes(b"\x73" * 32)
        public = private.public_key()
        payload = {"schema": source.REQUEST_PAYLOAD_SCHEMA,
            "sourceRevision": source.policy.authority.SOURCE_REVISION,
            "purpose": source.policy.PURPOSE, "operation": source.planner.OPERATION,
            "policyDigest": "sha256:" + "1" * 64,
            "plannerRequestDigest": "sha256:" + "2" * 64,
            "requestId": "3" * 64, "issuedAtEpochNs": EPOCH, "expiresAtEpochNs": EPOCH + AGE}
        raw = source.planner.signing._sign(payload, source.REQUEST_SCHEMA,
            source.MAX_REQUEST_BYTES, private, public, work())
        observed = source._read_request(raw, work())
        self.assertEqual(observed["payload"], payload)
        self.assertEqual(raw, json.dumps(observed, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii"))
        unsigned = source.policy.capability._wire(payload, source.capture._SharedLedger(work()),
            source.MAX_REQUEST_BYTES, 64)
        source.policy.capability._signature(public, observed["signatureBase64Url"],
            source.REQUEST_SCHEMA, unsigned, source.capture._SharedLedger(work()))
        with self.assertRaises(InvalidSignature):
            source.policy.capability._signature(public, observed["signatureBase64Url"],
                source.REQUEST_SCHEMA + "/other", unsigned, source.capture._SharedLedger(work()))
        for changed in (dict(payload, expiresAtEpochNs=True), dict(payload, requestId="3" * 63),
                dict(payload, extra="not admitted"), dict(payload, operation="jit.assertion.issue")):
            with self.subTest(change=tuple(changed)), self.assertRaises(ValueError):
                source._request_shape(changed)
        with self.assertRaises(ValueError):
            source._read_request(raw + b"\n", work())

    def test_policy_clock_checks_final_continuity_against_shorter_signed_expiry(self):
        state = {"elapsed": 100, "calls": 0, "armed": False}

        def continuity(epoch, monotonic):
            if state["armed"]:
                state["calls"] += 1
                # The third owner call is after the guard's genuine _fresh.
                if state["calls"] == 3:
                    state["elapsed"] = 2000
            return max(epoch, EPOCH + state["elapsed"]), max(monotonic, MONOTONIC + state["elapsed"])

        with clocks(state):
            current = source.policy._clock({"issuedAtEpochNs": EPOCH, "expiresAtEpochNs": EPOCH + 1000},
                WINDOW, WINDOW[4], work(), continuity)
            state["armed"] = True
            with self.assertRaises(ValueError):
                current()
            self.assertGreaterEqual(state["calls"], 3)
            self.assertLess(EPOCH + state["elapsed"], WINDOW[3])

    def test_cold_policy_clock_checks_after_the_final_inherited_sample(self):
        state = {"elapsed": 100, "armed": False}
        actual = source.planner._fresh

        def observed(*args, **kwargs):
            result = actual(*args, **kwargs)
            if state["armed"]:
                state["elapsed"] = 2000
            return result

        with clocks(state), patch.object(source.planner, "_fresh", side_effect=observed):
            current = source.policy._clock({"issuedAtEpochNs": EPOCH, "expiresAtEpochNs": EPOCH + 1000},
                None, None, work(), None)
            state["armed"] = True
            with self.assertRaises(ValueError):
                current()

    def test_original_lifetime_refuses_reset_replacement_rollback_and_expiry(self):
        for mutation in ("counter", "limits", "backward", "expiry"):
            state = {"elapsed": 100}
            with self.subTest(mutation=mutation), clocks(state):
                meter = work()
                lifetime = dynamic._Lifetime(meter)
                lifetime.narrow(EPOCH, EPOCH + 1000)
                meter.charge(input_bytes=17)
                lifetime.current()
                if mutation == "counter":
                    meter.input_bytes -= 1
                elif mutation == "limits":
                    meter.limits = QueryReadValidationLimits()
                elif mutation == "backward":
                    state["elapsed"] = 99
                else:
                    state["elapsed"] = 1000
                with self.assertRaises((RuntimeError, ValueError)):
                    lifetime.current()

    def test_staging_codec_has_exact_raw7_and_separate_ack_only(self):
        originals = (b"{}",) * 7
        self.assertIs(staging._originals(originals, response=False), originals)
        self.assertEqual(staging._originals((b"staged", b"sha256:" + b"a" * 64), response=True)[0], b"staged")
        for values, response in ((originals[:6], False), (list(originals), False),
                ((bytearray(b"{}"), *originals[1:]), False), ((b"ready!", b"sha256:" + b"a" * 64), True)):
            with self.subTest(response=response), self.assertRaises(staging.issuance.AuthorityTransportError):
                staging._originals(values, response=response)
        self.assertEqual(staging.REQUEST_HEADER_BYTES, 8 + 8 * len(staging.REQUEST_LIMITS))
        self.assertLess(staging.REQUEST_HEADER_BYTES + staging.MAX_ORIGINAL_BYTES
            + staging.RESPONSE_HEADER_BYTES + sum(staging.RESPONSE_LIMITS), 64 * 1024 * 1024)

    def test_actual_cold_and_permission_source_order_and_no_static_file_replacement(self):
        entry = body("oidc_session_activation_request_dynamic_entrypoint.py", "main")
        self.assertLess(entry.index("issuance._verify_planning_on_work"), entry.index("fixed._open_material"))
        self.assertLess(entry.index("fixed._keys_on_work"), entry.index("transport._send_response"))
        self.assertLess(entry.index("transport._send_response"), entry.index("os.setresuid"))
        self.assertLess(entry.index("os.setresuid"), entry.index("runner._run_on_work"))
        self.assertNotIn("BOOTSTRAP_PATH", entry)
        self.assertNotIn("os.replace", entry)
        request = body("control_plane_oidc_session_activation_request_issuance.py", "_prepare_on_permission")
        self.assertLess(request.index("request_payload = issuer._read_request"), request.index("transport._socket_request_on_work"))
        self.assertIn("return originals[3], live_window, deadline_ns", request)
        self.assertNotIn("owner._material =", request)
        dynamic_serve = body("authority_oidc_session_activation_planner_service.py", "_serve_dynamic_connection")
        self.assertLess(dynamic_serve.index("PLANNER_REQUEST_DOMAIN"), dynamic_serve.index("self._prepare_on_work"))
        self.assertNotIn("_ValidationWork(", dynamic_serve)
        self.assertNotIn("_open_on_work(", dynamic_serve)
        final = body("authority_oidc_session_activation_request_issuance.py", "_verify_request")
        self.assertLess(final.rindex("capability._canonical"), final.rindex("current()"))
        self.assertEqual(source.policy.MAX_POLICY_AGE_NS, 7200 * 1_000_000_000)
        self.assertEqual(source.planner.MAX_RECEIPT_AGE_NS, 300 * 1_000_000_000)


if __name__ == "__main__":
    unittest.main()
