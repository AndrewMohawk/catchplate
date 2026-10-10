#!/usr/bin/env python3
"""Inert parser checks (--pure), plus disposable Unix fixtures (default).

Unix unit fixtures map only the relay UID/GID constants to the test process,
but use real SO_PEERCRED, inodes, modes, sockets and protocol bytes. They do not
prove deployment cross-UID permissions; the separate connected suite does.
No real pilot path, browser, application owner, database or Internet is used.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from serverware import operator_notification_pilot_source as source

NOW_NS = 2_000_000_000_123_456_789
SELECTION = "sha256:" + "1" * 64
ATTEMPT = "sha256:" + "2" * 64
READINESS = "sha256:" + "3" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event_digest(status):
    binding = {key: status[key] for key in ("attemptSha256", "readinessSha256", "attemptNumber",
        "eventType", "sourceSha256", "sourceExpiresAtUnixNanos")}
    return "sha256:" + hashlib.sha256(canonical(binding).encode("ascii")).hexdigest()


def status_payload(phase="security_key_available", *, now_ns=NOW_NS):
    available = phase in source.AVAILABLE_PHASES
    setup = str(now_ns + 120_000_000_007)
    expiry = setup if phase == "prepare_available" else str(now_ns + 30_000_000_003)
    status = {"schema": "serverware.pilotActionStatus/v1", "attemptSha256": ATTEMPT,
        "readinessSha256": READINESS, "phase": phase, "actionAvailable": available,
        "attemptNumber": 0 if phase == "prepare_available" else 1,
        "sourceSha256": READINESS if phase == "prepare_available" else "sha256:" + "4" * 64,
        "setupExpiresAtUnixNanos": setup, "sourceExpiresAtUnixNanos": expiry,
        "reviewPath": "/pilot-prelaunch/action-status/" + ATTEMPT[7:] + "/" + READINESS[7:],
        "eventType": "native_pilot." + phase if available else None,
        "eventId": None, "automaticRetryAllowed": False, "enrollmentVerified": False}
    if available:
        status["eventId"] = event_digest(status)
    else:
        status["sourceSha256"] = None
        if phase != "expired":
            status["sourceExpiresAtUnixNanos"] = None
    return status


def relay_envelope(status=None, *, state="observed"):
    return {"schema": "serverware.pilotObservationRelay/v1", "selectionSha256": SELECTION,
        "state": state, "observation": status_payload() if state == "observed" and status is None else status}


def http_response(envelope):
    body = envelope if type(envelope) is bytes else canonical(envelope).encode("ascii")
    return (b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode("ascii") + b"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + body)


def config_json(path):
    return canonical({"schema": "serverware.operatorPilotNotificationSource/v1",
        "socketPath": str(path), "relayUid": 1000, "selectionSha256": SELECTION,
        "attemptSha256": ATTEMPT, "nativeOrigin": source.NATIVE_ORIGIN})


def inert_config():
    # Parser-only construction, deliberately not filesystem/source admission.
    return source.PilotSourceConfig("/inert/observation.sock", 1000, SELECTION,
        ATTEMPT, source.NATIVE_ORIGIN, (("inert-only",),))


def action_payload(status=None):
    status = status_payload() if status is None else status
    record = {"schema": "serverware.nativePilotNotificationObservation/v1",
        "selection_sha256": SELECTION, "observation": status}
    binding = {"selection_sha256": SELECTION, "native_event_id": status["eventId"]}
    event_id = "sha256:" + hashlib.sha256(canonical(binding).encode("ascii")).hexdigest()
    summary = {"prepare_available": "Prepare the native pilot",
        "security_key_available": "Use your security key for the native pilot",
        "confirmation_available": "Confirm the native pilot action"}[status["phase"]]
    return {"schema": "serverware.operatorNotification/v1", "channel": "action_required",
        "source": {"event_id": event_id, "event_hash": "sha256:" + "5" * 64,
            "event_type": "native_pilot.phase_observed", "created_at": "2026-10-10T12:00:00+00:00"},
        "summary": summary, "review_path": status["reviewPath"], "details": {"native_pilot": record}}


class PureTests(unittest.TestCase):
    def setUp(self):
        self.config = inert_config()

    def observation(self, status=None, **kwargs):
        return source._observation(self.config, relay_envelope(status, **kwargs))

    def test_import_is_inert_and_absent_configuration_has_no_io(self):
        for module in ("serverware.db", "serverware.config", "serverware.app", "serverware.crypto",
                "serverware.operator_demo", "serverware.operator_notification_store"):
            self.assertNotIn(module, sys.modules)
        with patch.object(source.os, "open", side_effect=AssertionError("no filesystem")), \
                patch.object(source.socket, "socket", side_effect=AssertionError("no sockets")):
            self.assertIsNone(source.admit_config(None))
            self.assertIsNone(source.admit_config(""))
            self.assertEqual(source.observation_summary(None, None)["state"], "not_configured")
            self.assertEqual(source.observation_summary(self.config, None)["state"], "not_observed")

    def test_configuration_closed_bounded_and_fixed_origin(self):
        valid = json.loads(config_json("/inert/observation.sock"))
        malformed = [dict(valid, extra=True), dict(valid, relayUid=True), dict(valid, relayUid=0),
            dict(valid, nativeOrigin="https://example.invalid"), dict(valid, selectionSha256="x"),
            dict(valid, attemptSha256="sha256:" + "A" * 64)]
        with patch.object(source, "_open_parent", side_effect=AssertionError("admission must refuse first")):
            for value in malformed:
                with self.subTest(value=value), self.assertRaisesRegex(source.SourceError, "^native notification source unavailable$"):
                    source.admit_config(canonical(value))
            for value in (" " * 4097, "é" * 2049, "{", "[]", "null", 1):
                with self.subTest(value=type(value)), self.assertRaises(source.SourceError):
                    source.admit_config(value)

    def test_all_available_phases_are_exact_immutable_notices(self):
        for phase in source.AVAILABLE_PHASES:
            with self.subTest(phase=phase):
                status = status_payload(phase)
                observation = self.observation(status)
                notice = source.observation_notice(self.config, observation, now_unix_nanos=NOW_NS)
                record = source.notice_record(notice)
                self.assertEqual(record["observation"], status)
                self.assertEqual(record["observation"]["sourceExpiresAtUnixNanos"], status["sourceExpiresAtUnixNanos"])
                with self.assertRaises(FrozenInstanceError):
                    notice.selection_sha256 = "changed"
                record["observation"]["phase"] = "changed"
                self.assertEqual(source.notice_record(notice)["observation"], status)
                payload = action_payload(status)
                self.assertEqual(source.review_url(self.config, payload), source.NATIVE_ORIGIN + status["reviewPath"])

    def test_original_nanosecond_deadline_not_rounded_up_or_renewed(self):
        status = status_payload()
        expiry = int(status["sourceExpiresAtUnixNanos"])
        observation = self.observation(status)
        payload = action_payload(status)
        self.assertIsNotNone(source.observation_notice(self.config, observation, now_unix_nanos=expiry - 1))
        self.assertIsNone(source.observation_notice(self.config, observation, now_unix_nanos=expiry))
        self.assertFalse(source.payload_is_unexpired(payload, now_unix_nanos=expiry))
        self.assertTrue(source.payload_is_unexpired(payload, now_unix_nanos=expiry - 1))
        # Historical records remain valid after expiry; never become live notices.
        self.assertEqual(source.validate_record(payload["details"]["native_pilot"])["observation"], status)
        summary = source.observation_summary(self.config, observation, now_unix_nanos=expiry)
        self.assertEqual(summary["state"], "observed")
        self.assertFalse(summary["action_available"])
        self.assertEqual(summary["source_expires_at_unix_nanos"], str(expiry))

    def test_nonactionable_states_never_produce_notice(self):
        phases = ("waiting", "cancelled", "response_captured", "action_in_progress",
            "preparing", "preparing_confirmation", "expired")
        for phase in phases:
            with self.subTest(phase=phase):
                observation = self.observation(status_payload(phase))
                self.assertIsNone(source.observation_notice(self.config, observation, now_unix_nanos=NOW_NS))
                summary = source.observation_summary(self.config, observation, now_unix_nanos=NOW_NS)
                self.assertFalse(summary["action_available"])
                self.assertEqual(summary["phase"], phase)
                with self.assertRaises(source.SourceError):
                    source.validate_record({"schema": "serverware.nativePilotNotificationObservation/v1",
                        "selection_sha256": SELECTION, "observation": status_payload(phase)})
        for state in ("waiting", "unavailable"):
            observation = self.observation(state=state)
            self.assertIsNone(source.observation_notice(self.config, observation, now_unix_nanos=NOW_NS))
            summary = source.observation_summary(self.config, observation, now_unix_nanos=NOW_NS)
            self.assertEqual(summary["observer_available"], state == "waiting")
            self.assertIsNone(summary["review_url"])

    def test_expired_exact_nonactionable_grammar(self):
        expired = status_payload("expired")
        self.observation(expired)
        for changes in ({"attemptNumber": 0}, {"sourceExpiresAtUnixNanos": None},
                {"sourceExpiresAtUnixNanos": str(int(expired["setupExpiresAtUnixNanos"]) + 1)}):
            with self.subTest(changes=changes), self.assertRaises(source.SourceError):
                self.observation(dict(expired, **changes))

    def test_closed_status_rejects_type_confusion_and_binding_changes(self):
        baseline = status_payload()
        changes = ({"extra": "untrusted"}, {"actionAvailable": 1}, {"attemptNumber": True},
            {"attemptNumber": 1.0}, {"attemptNumber": 33}, {"automaticRetryAllowed": True},
            {"enrollmentVerified": True}, {"eventId": "sha256:" + "9" * 64},
            {"sourceSha256": READINESS}, {"attemptSha256": READINESS}, {"readinessSha256": ATTEMPT},
            {"reviewPath": "https://example.invalid/"}, {"eventType": "approval.requested"},
            {"setupExpiresAtUnixNanos": "01"}, {"sourceExpiresAtUnixNanos": 123},
            {"sourceExpiresAtUnixNanos": str(2**63)}, {"phase": "anything"}, {"phase": []})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(source.SourceError):
                self.observation(dict(baseline, **change))
        prepare = status_payload("prepare_available")
        for change in ({"attemptNumber": 1}, {"sourceSha256": ATTEMPT},
                {"sourceExpiresAtUnixNanos": str(NOW_NS + 1)}):
            value = dict(prepare, **change)
            value["eventId"] = event_digest(value)
            with self.subTest(change=change), self.assertRaises(source.SourceError):
                self.observation(value)

    def test_closed_relay_json_and_duplicate_names(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', "[" * 2000, "x" * 8193):
            with self.subTest(raw=raw[:30]), self.assertRaises(source.SourceError):
                source._json(raw)
        wrapper = relay_envelope()
        for change in ({"extra": True}, {"selectionSha256": ATTEMPT}, {"state": "ready"},
                {"state": "waiting"}, {"observation": None}, {"state": []}):
            with self.subTest(change=change), self.assertRaises(source.SourceError):
                source._observation(self.config, dict(wrapper, **change))

    def test_fixed_http_framing_and_total_bound(self):
        good = http_response(relay_envelope())
        self.assertEqual(source._json(source._wire_body(good)), relay_envelope())
        bad = (good.replace(b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"),
            good.replace(b"Content-Type: application/json", b"Content-Type: text/plain"),
            good.replace(b"Connection: close", b"Connection: close\r\nTransfer-Encoding: chunked"),
            good.replace(b"Content-Length: ", b"Content-Length: 0"), good + b"x",
            good.replace(b"Cache-Control: no-store", b"Connection: close"))
        for wire in bad:
            with self.subTest(wire=wire[:40]), self.assertRaises(source.SourceError):
                source._wire_body(wire)
        body = canonical(relay_envelope()).encode("ascii")
        while len(http_response(body)) < 8192:
            body += b" "
        self.assertEqual(len(http_response(body)), 8192)
        self.assertEqual(source._json(source._wire_body(http_response(body))), relay_envelope())
        with self.assertRaises(source.SourceError):
            source._wire_body(http_response(body + b" "))

    def test_payload_closed_projection_and_native_url(self):
        payload = action_payload()
        self.assertTrue(source.payload_is_unexpired(payload, now_unix_nanos=NOW_NS))
        variants = [dict(payload, extra=True), dict(payload, channel="audit_log"),
            dict(payload, review_path="/#audit"), dict(payload, summary="custom"),
            dict(payload, details={"native_pilot": payload["details"]["native_pilot"], "secret": "no"}),
            dict(payload, source=dict(payload["source"], event_id=ATTEMPT)),
            dict(payload, source=dict(payload["source"], created_at="untrusted<script>"))]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(source.SourceError):
                source.review_url(self.config, value)
            self.assertFalse(source.payload_is_unexpired(value, now_unix_nanos=NOW_NS))
        with self.assertRaises(source.SourceError):
            source.review_url(replace(self.config, native_origin="https://example.invalid"), payload)
        with self.assertRaises(source.SourceError):
            source.review_url(replace(self.config, selection_sha256=ATTEMPT), payload)

    def test_currentness_fresh_exact_source_and_expiry_after_poll(self):
        payload = action_payload()
        observation = self.observation()
        with patch.object(source, "read_observation", return_value=observation) as read, \
                patch.object(source.time, "time_ns", return_value=NOW_NS):
            self.assertTrue(source.payload_is_current(self.config, payload))
            read.assert_called_once_with(self.config)
        for observed in (self.observation(status_payload("confirmation_available")), self.observation(state="unavailable")):
            with patch.object(source, "read_observation", return_value=observed), \
                    patch.object(source.time, "time_ns", return_value=NOW_NS):
                self.assertFalse(source.payload_is_current(self.config, payload))
        expiry = int(status_payload()["sourceExpiresAtUnixNanos"])
        # It can expire during the poll, or just after the poll's own check.
        for ticks in ([NOW_NS, expiry], [NOW_NS, expiry - 1, expiry]):
            with patch.object(source, "read_observation", return_value=observation), \
                    patch.object(source.time, "time_ns", side_effect=ticks):
                self.assertFalse(source.payload_is_current(self.config, payload))
        with patch.object(source, "read_observation", side_effect=source.SourceError("secret")), \
                patch.object(source.time, "time_ns", return_value=NOW_NS):
            self.assertFalse(source.payload_is_current(self.config, payload))
        self.assertEqual(str(source.SourceError("secret")), "native notification source unavailable")


class RelayFixture:
    """Local protocol fixture; UID/GID mapping is explicitly not deployment proof."""

    def __enter__(self):
        self.stack = ExitStack()
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="sw-notice-"))
        self.parent = Path(self.temp) / "observer"
        self.parent.mkdir(mode=0o750)
        os.chmod(self.parent, 0o750)
        self.path = self.parent / "observation.sock"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path))
        os.chmod(self.path, 0o660)
        self.socket.listen(4)
        self.socket.settimeout(0.1)
        self.stack.enter_context(patch.object(source, "_RELAY_UID", os.getuid()))
        self.stack.enter_context(patch.object(source, "_RELAY_GID", os.getgid()))
        self.response = http_response(relay_envelope())
        self.on_request = None
        self.requests = []
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self.config = source.admit_config(config_json(self.path))
        return self

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    connection.settimeout(1)
                    data = bytearray()
                    while not data.endswith(b"\r\n\r\n") and len(data) < 256:
                        chunk = connection.recv(256 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                    self.requests.append(bytes(data))
                    if self.on_request is not None:
                        self.on_request()
                    connection.sendall(self.response)
            except OSError:
                pass  # Timeout/oversize refusal may deliberately close early.
            except Exception as exc:
                self.errors.append(type(exc).__name__)

    def __exit__(self, *args):
        self.stop.set()
        self.socket.close()
        self.thread.join(2)
        self.stack.close()
        if self.thread.is_alive() or self.errors:
            raise AssertionError("disposable relay fixture did not stop cleanly")


class UnixTests(unittest.TestCase):
    def test_real_unix_protocol_peer_and_one_fixed_request(self):
        with RelayFixture() as relay:
            result = source.read_observation(relay.config)
            self.assertEqual(result.state, "observed")
            self.assertEqual(relay.requests, [b"GET /v1/observation HTTP/1.0\r\n\r\n"])
            self.assertIsNotNone(source.observation_notice(relay.config, result, now_unix_nanos=NOW_NS))

    def test_replaced_socket_is_not_readopted_and_wrong_mode_refuses(self):
        with RelayFixture() as relay:
            relay.path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as substitute:
                substitute.bind(str(relay.path))
                os.chmod(relay.path, 0o660)
                with self.assertRaises(source.SourceError):
                    source.read_observation(relay.config)
            self.assertEqual(relay.requests, [])
        with RelayFixture() as relay:
            os.chmod(relay.parent, 0o770)
            with self.assertRaises(source.SourceError):
                source.read_observation(relay.config)

    def test_replacement_after_connection_and_during_response_refuses(self):
        with RelayFixture() as relay:
            # The already-connected socket remains alive; pathname replacement
            # must still invalidate the observation after the complete read.
            def replace_entry():
                relay.path.unlink()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as substitute:
                    substitute.bind(str(relay.path))
                    os.chmod(relay.path, 0o660)
            relay.on_request = replace_entry
            with self.assertRaises(source.SourceError):
                source.read_observation(relay.config)
            self.assertEqual(len(relay.requests), 1)

    def test_symlink_parent_and_endpoint_are_not_admitted(self):
        with RelayFixture() as relay:
            alias = Path(relay.temp) / "alias"
            alias.symlink_to(relay.parent, target_is_directory=True)
            with self.assertRaises(source.SourceError):
                source.admit_config(config_json(alias / "observation.sock"))
            real = relay.parent / "real.sock"
            relay.path.rename(real)
            relay.path.symlink_to(real)
            with self.assertRaises(source.SourceError):
                source.admit_config(config_json(relay.path))

    def test_peer_refusal_overflow_and_no_retry(self):
        with RelayFixture() as relay:
            with patch.object(source, "_peer_uid", return_value=os.getuid() + 1):
                with self.assertRaises(source.SourceError):
                    source.read_observation(relay.config)
        with RelayFixture() as relay:
            relay.response = b"x" * 8193
            with self.assertRaises(source.SourceError):
                source.read_observation(relay.config)
            self.assertEqual(len(relay.requests), 1)

    def test_total_timeout_and_exact_wire_bound(self):
        with RelayFixture() as relay:
            relay.on_request = lambda: time.sleep(0.15)
            started = time.monotonic()
            with patch.object(source, "_TIMEOUT", 0.05), self.assertRaises(source.SourceError):
                source.read_observation(relay.config)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(len(relay.requests), 1)
        with RelayFixture() as relay:
            body = canonical(relay_envelope()).encode("ascii")
            while len(http_response(body)) < 8192:
                body += b" "
            relay.response = http_response(body)
            self.assertEqual(len(relay.response), 8192)
            self.assertEqual(source.read_observation(relay.config).state, "observed")


if __name__ == "__main__":
    if "--pure" in sys.argv:
        sys.argv.remove("--pure")
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PureTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main(verbosity=2)
