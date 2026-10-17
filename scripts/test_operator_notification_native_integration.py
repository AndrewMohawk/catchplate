#!/usr/bin/env python3
"""Root-run, network-none native-observation/notification boundary checks.

The root test parent creates only disposable synthetic state, starts a relay as
UID 1000:GID 10001 and an application worker as UID/GID 10001. Real socket file
ownership and SO_PEERCRED admission remain intact. The synthetic relay is not a
native ceremony. Only the outbound TLS fixture's DNS/IP/dial/trust-root seams
map its exact synthetic receiver to loopback. No real destination is contacted.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import test_operator_notification_store as fixtures
import test_operator_notification_transport as tls_fixture

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = str(Path(__file__).resolve())
PILOT_ENV = "CATCHPLATE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON"
SELECTION, ATTEMPT, READINESS = ("sha256:" + char * 64 for char in "abc")
NATIVE_ORIGIN = "https://catchplate.example.com"
REVIEW_PATH = "/pilot-prelaunch/action-status/" + ATTEMPT[7:] + "/" + READINESS[7:]
DESTINATION = "https://receiver.example.test/notification/SYNTHETIC_SECRET_URL_CANARY?token=PRIVATE_CANARY"
ACK = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def observation(expiry, *, available):
    value = {"schema": "catchplate.pilotActionStatus/v1", "attemptSha256": ATTEMPT,
        "readinessSha256": READINESS, "phase": "prepare_available" if available else "action_in_progress",
        "actionAvailable": available, "attemptNumber": 0, "sourceSha256": READINESS if available else None,
        "setupExpiresAtUnixNanos": str(expiry), "sourceExpiresAtUnixNanos": str(expiry) if available else None,
        "reviewPath": REVIEW_PATH, "eventType": "native_pilot.prepare_available" if available else None,
        "eventId": None, "automaticRetryAllowed": False, "enrollmentVerified": False}
    if available:
        binding = {key: value[key] for key in ("attemptSha256", "readinessSha256", "attemptNumber",
            "eventType", "sourceSha256", "sourceExpiresAtUnixNanos")}
        value["eventId"] = "sha256:" + hashlib.sha256(canonical(binding).encode("ascii")).hexdigest()
    return {"schema": "catchplate.pilotObservationRelay/v1", "selectionSha256": SELECTION,
        "state": "observed", "observation": value}


def relay(path, scenario, expiry):
    assert os.getuid() == 1000 and os.getgid() == 10001
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        os.chmod(path, 0o660)
        listener.listen(2)
        listener.settimeout(2)
        print('{"ready":true}', flush=True)
        count, deadline = 0, time.monotonic() + 80
        while time.monotonic() < deadline and count < 16:
            try:
                peer, _ = listener.accept()
            except TimeoutError:
                continue
            with peer:
                peer.settimeout(2)
                request = bytearray()
                while not request.endswith(b"\r\n\r\n") and len(request) <= 64:
                    chunk = peer.recv(65 - len(request))
                    if not chunk:
                        break
                    request.extend(chunk)
                assert request == b"GET /v1/observation HTTP/1.0\r\n\r\n"
                # Story: action read + final check + duplicate poll, then the
                # action is no longer available before its audit copy sends.
                available = count < (3 if scenario == "story" else 1)
                raw = canonical(observation(expiry, available=available)).encode("ascii")
                peer.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(raw)).encode("ascii")
                    + b"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + raw)
                count += 1


@contextmanager
def local_tls(fixture, receiver):
    transport, original_socket = fixture.transport, socket.socket
    connects = []

    class TestSocket(original_socket):
        def connect(self, address):
            if self.family == socket.AF_UNIX:
                assert type(address) is str and address.startswith("/proc/self/fd/")
                assert address.endswith("/observation.sock")
                return super().connect(address)
            assert address == ("127.0.0.1", 443)
            connects.append(address)
            return super().connect(("127.0.0.1", receiver.port))

    def context():
        value = ssl.create_default_context(cafile=str(tls_fixture.TlsTests.root / "cert.pem"))
        value.set_alpn_protocols(["http/1.1"])
        assert value.check_hostname and value.verify_mode == ssl.CERT_REQUIRED
        return value

    def admit(_destination, addresses):
        assert addresses == ((socket.AF_INET, "127.0.0.1"),)

    with patch.object(transport, "_resolve", return_value=((socket.AF_INET, "127.0.0.1"),)), \
            patch.object(transport, "_admit_addresses", side_effect=admit), \
            patch.object(transport.socket, "socket", TestSocket), \
            patch.object(transport, "_tls_context", side_effect=context):
        yield
    assert connects == [("127.0.0.1", 443)]


def assert_no_store_lock(fixture):
    from catchplate import operator_publication
    try:
        operator_publication.assert_held()
    except operator_publication.PublicationError:
        pass
    else:
        raise AssertionError("source read retained publication ownership")
    with closing(fixture.db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.rollback()


def run_app(scenario, raw_config):
    assert os.getuid() == os.getgid() == 10001
    case = unittest.TestCase()
    fixtures.configure_environment(case)
    case.environment[PILOT_ENV] = raw_config
    os.environ.clear()
    os.environ.update(case.environment)
    fixture = fixtures.Fixture()
    from catchplate import operator_notifications as worker, operator_notification_pilot_source as source
    assert fixture.store.ACTION_SOURCE_AVAILABLE is False
    for slot in ("action_required.webhook", "audit_log.webhook"):
        fixture.save(slot, url=DESTINATION, event_types=["native_pilot.prepare_available"])
    # Status does not admit paths or perform a socket poll, even when configured.
    with patch.object(source, "admit_config", side_effect=AssertionError("status admitted filesystem")), \
            patch.object(source, "read_observation", side_effect=AssertionError("status polled source")):
        initial = worker.status()["capabilities"]["native_hardware"]
        assert initial["configured"] and not initial["source_available"]
        assert initial["last_observation"]["state"] == "not_observed"
    original_read, original_admit = source.read_observation, source.admit_config
    reads = []

    def read(config):
        assert_no_store_lock(fixture)
        result = original_read(config)
        reads.append(result.state)
        return result

    tls_fixture.TlsTests.setUpClass()
    try:
        with patch.object(source, "read_observation", side_effect=read), \
                patch.object(source, "admit_config", wraps=original_admit) as admitted:
            with tls_fixture._Receiver(tls_fixture.TlsTests.server_context, [ACK]) as receiver:
                with local_tls(fixture, receiver):
                    assert worker.run_once()
            assert not receiver.errors
            if scenario == "changed":
                assert receiver.requests == []
                with closing(fixture.db.connect()) as connection:
                    row = connection.execute("SELECT status,last_code FROM operator_notification_deliveries "
                        "WHERE slot='action_required.webhook'").fetchone()
                    assert tuple(row) == ("suppressed", "native_source_unavailable")
            else:
                assert len(receiver.requests) == 1
                payload = json.loads(receiver.requests[0][1])
                fixture.clean_public(payload)
                assert payload["channel"] == "action_required" and "test" not in payload
                assert payload["review_url"] == NATIVE_ORIGIN + REVIEW_PATH
                assert payload["details"]["native_pilot"]["observation"]["sourceExpiresAtUnixNanos"] \
                    == os.environ["TEST_PILOT_EXPIRY"]
                # Repeat the same real closed observation: deterministic audit
                # idempotency must not create another delivery or renew expiry.
                duplicate = worker._poll_pilot()
                result = fixture.store.record_native_observation(duplicate, worker._now())
                assert result["recorded"] is False
                status = worker.status()["capabilities"]["native_hardware"]
                original = status["last_observation"]
                assert original["action_available"] and original["phase"] == "prepare_available"
                with patch.object(worker, "_now", return_value=original["observed_at_epoch_ms"] + 15000):
                    stale = worker.status()["capabilities"]["native_hardware"]["last_observation"]
                    assert stale["state"] == "observed" and not stale["action_available"]
                    assert stale["review_url"] == original["review_url"]
            # Both branches now have a nonactionable source. Historical audit
            # delivery remains independent of live action currentness.
            with tls_fixture._Receiver(tls_fixture.TlsTests.server_context, [ACK]) as audit_receiver:
                with local_tls(fixture, audit_receiver):
                    assert worker.run_once()
            assert not audit_receiver.errors and len(audit_receiver.requests) == 1
            audit = json.loads(audit_receiver.requests[0][1])
            fixture.clean_public(audit)
            assert audit["channel"] == "audit_log" and audit["source"]["event_type"] == "native_pilot.phase_observed"
            assert audit["review_url"] == "https://console.example.com/#audit"
            assert not worker.run_once()
            assert admitted.call_count == 1
            final = worker.status()["capabilities"]["native_hardware"]
            assert final["source_available"] and not final["last_observation"]["action_available"]
            assert final["last_observation"]["phase"] == "action_in_progress"
            assert raw_config not in canonical(worker.status())
            with closing(fixture.db.connect()) as connection:
                assert connection.execute("SELECT count(*) FROM audit_events WHERE event_type='native_pilot.phase_observed'").fetchone()[0] == 1
                assert connection.execute("SELECT count(*) FROM operator_notification_deliveries").fetchone()[0] == 2
            assert fixture.db.verify_audit_chain()["ok"]
            return {"real_cross_uid": True, "observer_reads_without_store_lock": len(reads),
                "native_action_posted": scenario == "story", "historical_audit_posted": True,
                "phase_change_suppressed": scenario == "changed", "single_source_record": True}
    finally:
        tls_fixture.TlsTests.tearDownClass()
        case.doCleanups()


def isolated(scenario):
    assert os.geteuid() == 0, "run this isolated test container as root for real UID separation"
    with tempfile.TemporaryDirectory(prefix="sw-native-notice-", dir="/tmp") as scratch:
        root = Path(scratch)
        # Ancestors are read-opened, not merely traversed. Secret application
        # state lives only in its own 0700 child, created after the UID drop.
        root.chmod(0o755)
        relay_dir, app_dir = root / "relay", root / "app"
        relay_dir.mkdir(mode=0o750)
        relay_dir.chmod(0o750)
        app_dir.mkdir(mode=0o700)
        os.chown(relay_dir, 1000, 10001)
        os.chown(app_dir, 10001, 10001)
        path = str(relay_dir / "observation.sock")
        expiry = time.time_ns() + 120_000_000_000
        raw_config = canonical({"schema": "catchplate.operatorPilotNotificationSource/v1",
            "socketPath": path, "relayUid": 1000, "selectionSha256": SELECTION,
            "attemptSha256": ATTEMPT, "nativeOrigin": NATIVE_ORIGIN})
        environment = {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}
        environment.update(PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(app_dir), TEST_PILOT_EXPIRY=str(expiry))
        process = subprocess.Popen([sys.executable, "-B", SCRIPT, "--relay", path, scenario, str(expiry)],
            cwd=ROOT, env=environment, user=1000, group=10001, extra_groups=[],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([process.stdout], [], [], 5)[0], "synthetic relay did not bind"
            assert process.stdout.readline().strip() == '{"ready":true}'
            result = subprocess.run([sys.executable, "-B", SCRIPT, "--app", scenario, raw_config],
                cwd=ROOT, env=environment, user=10001, group=10001, extra_groups=[],
                capture_output=True, text=True, timeout=65)
            assert result.returncode == 0, "\n".join(result.stderr.splitlines()[-50:])
            assert "PRIVATE_CANARY" not in result.stdout
            return json.loads(result.stdout)
        finally:
            process.terminate()
            process.communicate(timeout=5)


class NativeNotificationIntegrationTests(unittest.TestCase):
    def test_real_unix_action_and_historical_audit_reach_verified_tls(self):
        result = isolated("story")
        self.assertTrue(result["real_cross_uid"] and result["native_action_posted"])
        self.assertTrue(result["historical_audit_posted"] and result["single_source_record"])

    def test_phase_change_after_tls_prevents_post_without_losing_audit_copy(self):
        result = isolated("changed")
        self.assertTrue(result["phase_change_suppressed"])
        self.assertFalse(result["native_action_posted"])
        self.assertTrue(result["historical_audit_posted"])


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) == 5 and sys.argv[1] == "--relay":
        relay(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif len(sys.argv) == 4 and sys.argv[1] == "--app":
        print(json.dumps(run_app(sys.argv[2], sys.argv[3]), sort_keys=True))
    else:
        unittest.main()
