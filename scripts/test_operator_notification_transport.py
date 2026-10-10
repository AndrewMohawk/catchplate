#!/usr/bin/env python3
"""Pure checks by default; --tls adds isolated loopback-only HTTPS receivers.

The TLS suite deliberately patches private DNS/address/port seams for synthetic
loopback traffic. Production admission stays default-deny and has no such API.
It never resolves or contacts a real webhook. Run TLS under network isolation.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from serverware import operator_notification_transport as t

SECRET = "synthetic-URL-path-canary-never-public"
URL = "https://receiver.example.test/" + SECRET + "?token=synthetic-query-canary"
SLACK = "https://hooks.slack.com/services/T123/B456/synthetic_slack_canary"


def payload() -> dict:
    return {"schema": "serverware.operatorNotification/v1", "channel": "audit_log",
        "source": {"event_id": "1", "event_hash": "a" * 64,
            "event_type": "credential.created", "created_at": "2026-10-10T00:00:00Z"},
        "summary": "Synthetic test, no action required", "review_path": "/#audit",
        "details": {}, "projection": "metadata_only", "delivery_id": "synthetic-delivery",
        "slot": "audit_log.webhook", "revision": 1,
        "review_url": "https://console.example.test/#audit", "test": True}


class PureTests(unittest.TestCase):
    def test_static_save_validation_has_no_network(self):
        with mock.patch.object(t, "_resolve", side_effect=AssertionError("no DNS")), \
                mock.patch.object(t.socket, "socket", side_effect=AssertionError("no socket")):
            for adapter, url in (("webhook", URL), ("slack", SLACK),
                    ("slack", SLACK.replace("hooks.slack.com", "hooks.slack-gov.com"))):
                self.assertIsNone(t.validate_destination(adapter, url, t.EgressPolicy()))

    def test_bad_url_grammars_are_secret_safe(self):
        bad = ["http://receiver.example.test/x", "https://u:p@receiver.example.test/x",
            "https://receiver.example.test/x#fragment", "https://receiver.example.test/x#",
            "https://receiver.example.test:8443/x", "https://receiver.example.test:0/x",
            "https://receiver.example.test:/x", "https://receiver.example.test:0443/x",
            "https://Receiver.example.test/x", "https://receiver.example.test./x",
            "https://receiver.example.test/x\r\nY:z", "https://receiver.example.test/a b",
            "https://receiver.example.test/%0d", "https://receiver.example.test/%7F",
            "https://receiver.example.test/%xx", "https://receiver.example.test/a\\b",
            "https://127.0.0.1/x", "https://[::1]/x", "https://2130706433/x",
            "https://localhost/x", "https://metadata.google.internal/x",
            "https://réceiver.example.test/x", "https://receiver.example.test/" + "x" * 4096]
        for url in bad:
            with self.subTest(url=url.split("/")[2]):
                with self.assertRaises(t.DestinationError) as failure:
                    t.validate_destination("webhook", url, t.EgressPolicy())
                self.assertEqual(str(failure.exception), "notification destination invalid")
                result = t.deliver("webhook", url, payload(), t.EgressPolicy())
                self.assertEqual((result.state, result.code), ("failed", "destination_invalid"))
                self.assertNotIn(url, repr(result))

    def test_slack_destination_closed_grammar(self):
        for url in (SLACK + "?x=y", SLACK + "?", SLACK + "/", SLACK.replace("hooks.slack.com", "slack.com"),
                SLACK.replace("/services/", "/api/"), SLACK.replace("B456", "B%34")):
            with self.assertRaises(t.DestinationError):
                t.validate_destination("slack", url, t.EgressPolicy())
        policy = t.EgressPolicy((t.EgressBinding("hooks.slack.com", 443, ("10.0.0.0/8",)),))
        with self.assertRaises(t.DestinationError):
            t.validate_destination("slack", SLACK, policy)

    def test_policy_parser_closed_and_separate(self):
        raw = '{"bindings":[{"host":"receiver.internal.test","port":8443,"cidrs":["10.20.0.0/16"]}]}'
        policy = t.parse_egress_policy(raw)
        self.assertEqual(policy.bindings[0], t.EgressBinding("receiver.internal.test", 8443, ("10.20.0.0/16",)))
        t.validate_destination("webhook", "https://receiver.internal.test:8443/secret", policy)
        bad = ("{}", '{"bindings":[],"bindings":[]}', '{"bindings":[],"other":1}',
            raw.replace('"cidrs":', '"other":'), raw.replace("10.20.0.0/16", "0.0.0.0/0"),
            raw.replace("10.20.0.0/16", "127.0.0.0/8"), raw.replace("10.20.0.0/16", "169.254.0.0/16"),
            raw.replace("10.20.0.0/16", "10.20.0.1/16"), raw.replace("8443", "true"), " " * 4097)
        for value in bad:
            with self.assertRaises(t.EgressPolicyError) as failure:
                t.parse_egress_policy(value)
            self.assertEqual(str(failure.exception), "notification egress policy invalid")

    def test_address_admission_all_answers_not_first_only(self):
        dest = t._destination("webhook", URL, t.EgressPolicy())
        t._admit_addresses(dest, ((socket.AF_INET, "1.1.1.1"), (socket.AF_INET6, "2606:4700:4700::1111")))
        bad = ("127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "100.100.100.200",
            "168.63.129.16", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1",
            "fd00:ec2::254", "fec0::1", "::ffff:127.0.0.1", "2002:7f00:1::", "2001:0::1")
        for value in bad:
            with self.assertRaises(t._Failure) as failure:
                t._admit_addresses(dest, ((socket.AF_INET, "1.1.1.1"),
                    (socket.AF_INET if ":" not in value else socket.AF_INET6, value)))
            self.assertEqual(failure.exception.code, "egress_denied")
        with self.assertRaises(t._Failure):
            t._admit_addresses(dest, ((socket.AF_INET6, "fec0::1"),))

    def test_private_policy_pins_network_and_never_metadata(self):
        policy = t.EgressPolicy((t.EgressBinding("receiver.internal.test", 443,
            ("10.0.0.0/8", "fc00::/7")),))
        dest = t._destination("webhook", "https://receiver.internal.test/a", policy)
        t._admit_addresses(dest, ((socket.AF_INET, "10.3.4.5"), (socket.AF_INET6, "fd11::1")))
        for value in ("1.1.1.1", "192.168.1.1", "127.0.0.1", "fd00:ec2::254"):
            with self.assertRaises(t._Failure):
                t._admit_addresses(dest, ((socket.AF_INET if ":" not in value else socket.AF_INET6, value),))

    def test_slack_plain_text_and_escaped_fallback(self):
        message = payload()
        message["summary"] = "<!channel> <@U123> & @here *not markdown*"
        body = json.loads(t._payload("slack", message))
        self.assertFalse(body["mrkdwn"])
        self.assertFalse(body["unfurl_links"])
        self.assertFalse(body["unfurl_media"])
        self.assertNotIn("<!channel>", body["text"])
        self.assertIn("&lt;!channel&gt;", body["text"])
        self.assertEqual(body["blocks"][0]["text"]["type"], "plain_text")
        self.assertNotIn("<!channel>", body["blocks"][0]["text"]["text"])
        self.assertNotIn("source", body)

    def test_payload_limits_and_closed_outer_fields_before_dns(self):
        for updates in ({"schema": "unknown"}, {"request": {"secret": SECRET}},
                {"summary": "x" * 16385}, {"details": {"bad": float("nan")}}):
            message = payload() | updates
            with mock.patch.object(t, "_resolve", side_effect=AssertionError("no DNS")):
                result = t.deliver("webhook", URL, message, t.EgressPolicy())
            self.assertEqual(result.code, "payload_invalid")
            self.assertNotIn(SECRET, repr(result))
        with self.assertRaises(t._Failure):
            t._payload("slack", payload() | {"summary": "x" * 1001})

    def test_result_closed_codes_and_retry_boundaries(self):
        for code in t.RETRYABLE_CODES:
            self.assertTrue(t.DeliveryResult("failed", code).retryable)
        for result in (t.DeliveryResult("outcome_unknown", "delivery_unknown"),
                t.DeliveryResult("failed", "http_rejected", 429),
                t.DeliveryResult("failed", "transport_unavailable"),
                t.DeliveryResult("acknowledged", "acknowledged", 200)):
            self.assertFalse(result.retryable)
        for args in (("failed", SECRET), ("outcome_unknown", "dns_timeout"),
                ("acknowledged", "acknowledged", True), ("failed", "http_rejected", 100)):
            with self.assertRaisesRegex(ValueError, "^notification delivery result invalid$"):
                t.DeliveryResult(*args)

    def test_dns_failure_never_leaks_or_opens_socket(self):
        with mock.patch.object(t, "_resolve", side_effect=t._Failure("dns_timeout")), \
                mock.patch.object(t.socket, "socket", side_effect=AssertionError("no socket")):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
        self.assertEqual(result.code, "dns_timeout")
        self.assertTrue(result.retryable)
        with mock.patch.object(t, "_resolve", side_effect=RuntimeError(SECRET)):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
        self.assertEqual(result.code, "transport_unavailable")
        self.assertNotIn(SECRET, repr(result))

    def test_dns_subprocess_timeout_kills_reaps_releases_slot(self):
        child = mock.MagicMock()
        child.__enter__.return_value = child
        child.communicate.side_effect = [subprocess.TimeoutExpired("fixed", 1), (b"", None)]
        with mock.patch.object(t.subprocess, "Popen", return_value=child) as factory:
            with self.assertRaises(t._Failure) as failure:
                t._resolve("receiver.example.test", 443, time.monotonic() + 1)
        self.assertEqual(failure.exception.code, "dns_timeout")
        child.kill.assert_called_once_with()
        self.assertEqual(child.communicate.call_count, 2)
        args, kwargs = factory.call_args
        self.assertEqual(args[0], [sys.executable, "-I", "-c", t._DNS_CODE])
        self.assertNotIn("receiver.example.test", repr(args))
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
        self.assertTrue(t._DNS_SLOTS.acquire(False))
        self.assertTrue(t._DNS_SLOTS.acquire(False))
        self.assertFalse(t._DNS_SLOTS.acquire(False))
        t._DNS_SLOTS.release()
        t._DNS_SLOTS.release()

    def test_dns_malformed_output_and_family_fail_closed(self):
        for output in (b"[]", b"invalid", b'[[2,"::1"]]', b'[[true,"127.0.0.1"]]',
                b'[[10,"fe80::1%eth0"]]', b"x" * 8193):
            child = mock.MagicMock(returncode=0)
            child.__enter__.return_value = child
            child.communicate.return_value = (output, None)
            with mock.patch.object(t.subprocess, "Popen", return_value=child):
                with self.assertRaises(t._Failure):
                    t._resolve("receiver.example.test", 443, time.monotonic() + 1)

    def test_dns_concurrency_saturated_is_safe_no_spawn(self):
        with mock.patch.object(t._DNS_SLOTS, "acquire", return_value=False), \
                mock.patch.object(t.subprocess, "Popen", side_effect=AssertionError("no spawn")):
            with self.assertRaises(t._Failure) as failure:
                t._resolve("receiver.example.test", 443, time.monotonic() + 1)
        self.assertEqual(failure.exception.code, "dns_unavailable")

    def test_private_answer_mixed_with_public_prevents_connect(self):
        with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),
                (socket.AF_INET, "127.0.0.1"))), \
                mock.patch.object(t.socket, "socket", side_effect=AssertionError("no socket")):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
        self.assertEqual(result.code, "egress_denied")
        self.assertFalse(result.retryable)

    def test_connect_failure_is_retryable_and_never_starts_tls(self):
        for exception, expected in ((TimeoutError(SECRET), "connect_timeout"),
                (OSError(SECRET), "connect_unavailable")):
            raw_socket = mock.MagicMock()
            raw_socket.connect.side_effect = exception
            with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),)), \
                    mock.patch.object(t.socket, "socket", return_value=raw_socket), \
                    mock.patch.object(t, "_tls_context", side_effect=AssertionError("no TLS")):
                result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
            self.assertEqual(result.code, expected)
            self.assertTrue(result.retryable)
            self.assertNotIn(SECRET, repr(result))
            raw_socket.close.assert_called_once_with()

    def test_even_injected_tls_verification_disable_is_refused(self):
        raw_socket = mock.MagicMock()
        context = mock.MagicMock(check_hostname=False, verify_mode=ssl.CERT_NONE)
        with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),)), \
                mock.patch.object(t.socket, "socket", return_value=raw_socket), \
                mock.patch.object(t, "_tls_context", return_value=context):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
        self.assertEqual(result.code, "tls_unavailable")
        context.wrap_socket.assert_not_called()

    def test_production_tls_context_never_honors_ambient_keylog(self):
        with tempfile.TemporaryDirectory(prefix="notification-keylog-canary-") as directory:
            keylog = Path(directory) / "must-not-exist.log"
            with mock.patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                context = t._tls_context()
            self.assertIsNone(context.keylog_filename)
            self.assertFalse(keylog.exists())
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_first_write_failure_is_unknown_never_safe_retry(self):
        raw_socket, tls = mock.MagicMock(), mock.MagicMock()
        tls.selected_alpn_protocol.return_value = "http/1.1"
        tls.sendall.side_effect = OSError(SECRET)
        context = mock.MagicMock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        context.wrap_socket.return_value = tls
        with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),)), \
                mock.patch.object(t.socket, "socket", return_value=raw_socket), \
                mock.patch.object(t, "_tls_context", return_value=context):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy())
        self.assertEqual(result, t.DeliveryResult("outcome_unknown", "delivery_unknown"))
        self.assertFalse(result.retryable)
        self.assertEqual(tls.sendall.call_count, 1)
        tls.close.assert_called_once_with()

    def test_dispatch_callback_after_tls_is_fail_closed_and_secret_safe(self):
        for returned, expected in ((False, "dispatch_cancelled"), (None, "dispatch_cancelled"),
                (1, "dispatch_cancelled"), (RuntimeError(SECRET), "transport_unavailable"),
                (TimeoutError(SECRET), "transport_unavailable"), (True, "delivery_unknown")):
            calls = []
            raw_socket, tls = mock.MagicMock(), mock.MagicMock()
            tls.selected_alpn_protocol.return_value = "http/1.1"
            context = mock.MagicMock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
            def handshake(*_args, **_kwargs):
                calls.append("tls")
                return tls
            def check():
                self.assertEqual(calls, ["tls"])
                calls.append("check")
                if isinstance(returned, Exception):
                    raise returned
                return returned
            def send(_request):
                calls.append("write")
                raise OSError(SECRET)
            context.wrap_socket.side_effect = handshake
            tls.sendall.side_effect = send
            with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),)), \
                    mock.patch.object(t.socket, "socket", return_value=raw_socket), \
                    mock.patch.object(t, "_tls_context", return_value=context):
                result = t.deliver("webhook", URL, payload(), t.EgressPolicy(), before_dispatch=check)
            self.assertEqual(result.code, expected)
            self.assertFalse(result.retryable)
            self.assertEqual(calls, ["tls", "check", "write"] if returned is True else ["tls", "check"])
            self.assertNotIn(SECRET, repr(result))
            tls.close.assert_called_once_with()

    def test_dispatch_callback_cannot_extend_original_deadline(self):
        clock = {"now": 0.0}
        raw_socket, tls = mock.MagicMock(), mock.MagicMock()
        tls.selected_alpn_protocol.return_value = "http/1.1"
        context = mock.MagicMock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        context.wrap_socket.return_value = tls
        def check():
            clock["now"] = t.TOTAL_TIMEOUT + 1
            return True
        with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "1.1.1.1"),)), \
                mock.patch.object(t.socket, "socket", return_value=raw_socket), \
                mock.patch.object(t, "_tls_context", return_value=context), \
                mock.patch.object(t.time, "monotonic", side_effect=lambda: clock["now"]):
            result = t.deliver("webhook", URL, payload(), t.EgressPolicy(), before_dispatch=check)
        self.assertEqual(result, t.DeliveryResult("failed", "deadline_exceeded"))
        self.assertFalse(result.retryable)
        tls.sendall.assert_not_called()


class _Receiver:
    """One TLS connection; no request/error logs and no outbound operations."""
    def __init__(self, context, chunks, delay=0):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(2)
        self.port = self.listener.getsockname()[1]
        self.context, self.chunks, self.delay = context, chunks, delay
        self.requests, self.errors = [], []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            raw, _ = self.listener.accept()
            with raw, self.context.wrap_socket(raw, server_side=True) as conn:
                conn.settimeout(2)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    request.extend(chunk)
                head, body = bytes(request).split(b"\r\n\r\n", 1)
                headers = dict(line.split(b": ", 1) for line in head.split(b"\r\n")[1:])
                size = int(headers[b"Content-Length"])
                while len(body) < size:
                    chunk = conn.recv(size - len(body))
                    if not chunk:
                        return
                    body += chunk
                self.requests.append((head, body))
                for chunk in self.chunks:
                    if self.delay:
                        time.sleep(self.delay)
                    conn.sendall(chunk)
        except (OSError, ssl.SSLError) as exc:
            self.errors.append(type(exc).__name__)
        finally:
            self.listener.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.thread.join(3)
        self.listener.close()
        if self.thread.is_alive():
            raise AssertionError("synthetic TLS receiver did not terminate")


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        cls.temp = tempfile.TemporaryDirectory(prefix="serverware-notification-tls-")
        cls.root = Path(cls.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic notification fixture")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("receiver.example.test"),
                x509.DNSName("hooks.slack.com")]), critical=False).sign(key, hashes.SHA256()))
        (cls.root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (cls.root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (cls.root / "key.pem").chmod(0o600)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(cls.root / "cert.pem", cls.root / "key.pem")
        cls.sni = []
        cls.server_context.set_servername_callback(lambda _socket, name, _context: cls.sni.append(name))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def call(self, receiver, adapter="webhook", *, url=None, context=None, timeout=2, before_dispatch=None):
        original_socket = socket.socket
        destination_url = url or (SLACK if adapter == "slack" else URL)
        connects = []
        class TestSocket(original_socket):
            def connect(self, address):
                if address != ("127.0.0.1", 443):
                    raise AssertionError("test attempted non-loopback contact")
                connects.append(address)
                return super().connect(("127.0.0.1", receiver.port))
        def context_factory():
            if context is not None:
                return context
            result = ssl.create_default_context(cafile=str(self.root / "cert.pem"))
            result.set_alpn_protocols(["http/1.1"])
            return result
        def test_admission(_destination, answers):
            if answers != ((socket.AF_INET, "127.0.0.1"),):
                raise AssertionError("test address policy escaped loopback")
        with mock.patch.object(t, "_resolve", return_value=((socket.AF_INET, "127.0.0.1"),)) as resolver, \
                mock.patch.object(t, "_admit_addresses", side_effect=test_admission), \
                mock.patch.object(t.socket, "socket", TestSocket), \
                mock.patch.object(t, "_tls_context", side_effect=context_factory), \
                mock.patch.object(t, "TOTAL_TIMEOUT", timeout), \
                mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1"}):
            result = t.deliver(adapter, destination_url, payload(), t.EgressPolicy(), before_dispatch=before_dispatch)
        self.assertEqual(resolver.call_count, 1)
        self.assertEqual(connects, [("127.0.0.1", 443)])
        self.assertNotIn(SECRET, repr(result))
        return result

    def test_generic_tls_exact_post_pinning_sni_and_no_ambient_proxy(self):
        with _Receiver(self.server_context, [b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"]) as receiver:
            result = self.call(receiver)
        self.assertEqual(result, t.DeliveryResult("acknowledged", "acknowledged", 202))
        self.assertEqual(len(receiver.requests), 1)
        head, body = receiver.requests[0]
        self.assertIn(b"POST /" + SECRET.encode() + b"?token=synthetic-query-canary HTTP/1.1", head)
        self.assertIn(b"Host: receiver.example.test", head)
        self.assertNotIn(b"Cookie:", head)
        self.assertNotIn(b"Proxy-Authorization:", head)
        self.assertEqual(json.loads(body), payload())
        self.assertEqual(self.sni[-1], "receiver.example.test")

    def test_actual_dns_process_timeout_kills_and_reaps_without_resolution(self):
        children = []
        original = subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with mock.patch.object(t, "_DNS_CODE", "import time; time.sleep(5)"), \
                mock.patch.object(t, "DNS_TIMEOUT", 0.05), \
                mock.patch.object(t.subprocess, "Popen", side_effect=spawn):
            with self.assertRaises(t._Failure) as failure:
                t._resolve("receiver.example.test", 443, time.monotonic() + 1)
        self.assertEqual(failure.exception.code, "dns_timeout")
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_slack_exact_plain_ack_and_rendered_body(self):
        with _Receiver(self.server_context, [b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok"]) as receiver:
            result = self.call(receiver, "slack")
        self.assertEqual(result.state, "acknowledged")
        self.assertEqual(json.loads(receiver.requests[0][1])["blocks"][0]["text"]["type"], "plain_text")
        self.assertEqual(self.sni[-1], "hooks.slack.com")

    def test_dispatch_callback_after_verified_tls_suppresses_without_post(self):
        for outcome, code in ((False, "dispatch_cancelled"),
                (RuntimeError(SECRET), "transport_unavailable"), (TimeoutError(SECRET), "transport_unavailable")):
            calls = []
            with _Receiver(self.server_context, []) as receiver:
                def check():
                    self.assertEqual(self.sni[-1], "receiver.example.test")
                    self.assertEqual(receiver.requests, [])
                    calls.append("check")
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                result = self.call(receiver, before_dispatch=check)
            self.assertEqual(result, t.DeliveryResult("failed", code))
            self.assertFalse(result.retryable)
            self.assertEqual(calls, ["check"])
            self.assertEqual(receiver.requests, [])

    def test_dispatch_callback_expiry_after_verified_tls_sends_no_post(self):
        calls = []
        original_clock, offset = time.monotonic, [0.0]
        with _Receiver(self.server_context, []) as receiver:
            def check():
                self.assertEqual(self.sni[-1], "receiver.example.test")
                calls.append("check")
                offset[0] = 10.0
                return True
            with mock.patch.object(t.time, "monotonic", side_effect=lambda: original_clock() + offset[0]):
                result = self.call(receiver, before_dispatch=check)
        self.assertEqual(result, t.DeliveryResult("failed", "deadline_exceeded"))
        self.assertFalse(result.retryable)
        self.assertEqual(calls, ["check"])
        self.assertEqual(receiver.requests, [])

    def test_current_dispatch_callback_allows_one_post(self):
        calls = []
        with _Receiver(self.server_context, [b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"]) as receiver:
            def check():
                self.assertEqual(receiver.requests, [])
                calls.append("check")
                return True
            result = self.call(receiver, before_dispatch=check)
        self.assertEqual(result, t.DeliveryResult("acknowledged", "acknowledged", 204))
        self.assertEqual(calls, ["check"])
        self.assertEqual(len(receiver.requests), 1)

    def test_slack_wrong_ack_is_terminal_not_retry(self):
        replies = [b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\nok\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\nok",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"]
        for reply in replies:
            with _Receiver(self.server_context, [reply]) as receiver:
                result = self.call(receiver, "slack")
            self.assertEqual(result.code, "acknowledgement_invalid")
            self.assertFalse(result.retryable)

    def test_redirect_and_negative_response_never_follow_or_retry(self):
        for status in (302, 429, 503):
            response = (f"HTTP/1.1 {status} Nope\r\nLocation: https://receiver.example.test/secret-target"
                "\r\nSet-Cookie: secret-cookie=never-send\r\nContent-Length: 0\r\n\r\n").encode()
            with _Receiver(self.server_context, [response]) as receiver:
                result = self.call(receiver)
            self.assertEqual(result, t.DeliveryResult("failed", "http_rejected", status))
            self.assertFalse(result.retryable)
            self.assertEqual(len(receiver.requests), 1)

    def test_lost_ack_and_bad_framing_outcome_unknown(self):
        replies = [b"", b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 32768 + b"\r\n\r\n"]
        for reply in replies:
            with _Receiver(self.server_context, [reply] if reply else []) as receiver:
                result = self.call(receiver)
            self.assertEqual(result.state, "outcome_unknown")
            self.assertFalse(result.retryable)
            self.assertEqual(len(receiver.requests), 1)

    def test_deadline_includes_slow_drip_headers_and_body(self):
        for chunks in ([b"HTTP/1.1 200 OK\r\n", b"X-One: 1\r\n", b"Content-Length: 0\r\n\r\n"],
                [b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", b"a", b"b", b"c", b"d"]):
            started = time.monotonic()
            with _Receiver(self.server_context, chunks, delay=0.08) as receiver:
                result = self.call(receiver, timeout=0.18)
                elapsed = time.monotonic() - started
            self.assertEqual(result.state, "outcome_unknown")
            self.assertLess(elapsed, 0.4)

    def test_untrusted_or_wrong_hostname_tls_sends_no_request(self):
        with _Receiver(self.server_context, []) as receiver:
            result = self.call(receiver, context=ssl.create_default_context())
        self.assertEqual(result.code, "tls_unavailable")
        self.assertTrue(result.retryable)
        self.assertEqual(receiver.requests, [])
        with _Receiver(self.server_context, []) as receiver:
            result = self.call(receiver, url=URL.replace("receiver.example.test", "other.example.test"))
        self.assertEqual(result.code, "tls_unavailable")
        self.assertEqual(receiver.requests, [])


if __name__ == "__main__":
    run_tls = "--tls" in sys.argv
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(PureTests))
    if run_tls:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TlsTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
