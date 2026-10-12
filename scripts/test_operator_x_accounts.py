#!/usr/bin/env python3
"""X lifecycle orchestration controls with explicit synthetic owner doubles.

These tests do NOT prove SQLite custody, readiness, TLS, provider acceptance or
proxy posting. The separate connected suite supplies real state owners. Here
the actual protocol/HTTP parser run over an in-memory socket; transaction/store
doubles make ordering and one-shot failure behaviour independently observable.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import serverware
from serverware import operator_x_accounts as accounts
from serverware import operator_x_oauth_profile as profiles
from serverware import operator_x_oauth_protocol as protocol
from serverware import operator_x_transport as transport
from serverware.http_client import HttpDeadline


def deny_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"} or event.startswith("sqlite3."):
        raise AssertionError("orchestration component test forbids external effects")


sys.addaudithook(deny_network)
OP = "8a9f4561-1045-4b67-9173-b186c6f76d7d"
CREDENTIAL = "8a9f4561-1045-4b67-9173-b186c6f76d7e"  # Public synthetic row UUID, not a token. gitleaks:allow
ACTOR = "synthetic-admin"
CANARY = "synthetic-private-X-canary"


def operation(status="connected", *, kind="consent"):
    return {"schema": accounts.OPERATION_SCHEMA, "operation_id": OP, "kind": kind,
        "status": status, "credential_id": CREDENTIAL, "reason": None,
        "created_at": "2026-10-12T12:00:00+00:00",
        "expires_at_epoch_ms": 1_900_000_000_000 if kind == "consent" else None}


def wire(body):
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


class Socket:
    def __init__(self, raw):
        self.raw = raw
        self.closed = False

    def settimeout(self, _value):
        pass

    def sendall(self, _raw):
        pass

    def recv(self, size):
        raw, self.raw = self.raw[:size], self.raw[size:]
        return raw

    def close(self):
        self.closed = True


class AccountsTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.profile = profiles.build_profile(client_id="synthetic-client", public_origin="https://operator.example.com")
        self.selection = SimpleNamespace(record={"operation_id": OP}, profile=self.profile,
            client_secret=CANARY, key_pin=object())
        self.used = False
        self.captures = []

        def consume(_conn, **options):
            if self.used:
                raise ValueError(CANARY)
            self.used = True
            self.events.append("consume")
            return {"intent": {"operation_id": OP, "actor_id": ACTOR},
                "work_id": None if options["error"] else OP,
                "selection": self.selection.record, "code_verifier": "v" * 43}

        def claim(_conn, _work, *, request, deadline):
            self.events.append("claim:" + request.phase)

        def capture(_conn, _work, value):
            self.events.append("capture:" + value.request.phase)
            self.captures.append(value)

        def adopt(_conn, _work, *, token, identity):
            self.events.append("adopt")
            self.assertEqual([value.request.phase for value in self.captures], ["code", "identity"])
            self.assertEqual(identity.subject, "123")
            self.assertEqual(token.access_token, CANARY)

        self.store = SimpleNamespace(consume_callback=consume, claim_contact=claim, capture=capture,
            adopt=adopt, status=lambda *_: operation("denied" if self.denied else "connected"),
            hold=lambda *_args, **_kwargs: self.events.append("hold") or operation("uncertain"))
        self.denied = False

        @contextmanager
        def transaction(_directory, *, writable):
            self.events.append("begin-write" if writable else "begin-read")
            try:
                yield object()
            except BaseException:
                self.events.append("rollback")
                raise
            else:
                self.events.append("commit" if writable else "read-end")

        @contextmanager
        def selection(*_args):
            yield self.selection

        for replacement in (patch.object(serverware, "operator_x_account_store", self.store, create=True),
                patch.object(accounts, "_transaction", transaction),
                patch.object(accounts.admission, "require_runtime", return_value=object()),
                patch.object(accounts.configuration, "_retained_selection", selection),
                patch.object(accounts.keys, "check_pin", return_value=None)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def responses(self, raw):
        streams = [Socket(item) for item in raw]

        def connect(_deadline):
            # A successful dispatch claim must have committed before any wire.
            self.assertEqual(self.events[-1], "commit")
            self.events.append("wire")
            self.assertTrue(streams)
            return streams.pop(0)

        return patch.object(transport, "_connect", side_effect=connect)

    def callback(self, **changes):
        return accounts.complete_callback(**{"state": "s" * 43, "browser_nonce": "n" * 43,
            "code": "code-private-canary", "error": None, **changes})

    def token(self):
        return json.dumps({"access_token": CANARY, "refresh_token": "refresh-" + CANARY,
            "token_type": "bearer", "expires_in": 3600,
            "scope": " ".join(protocol.SCOPES)}).encode()

    def test_complete_callback_claims_and_retains_each_response_before_adoption(self):
        with self.responses([wire(self.token()), wire(b'{"data":{"id":"123","username":"fixture","name":"Fixture"}}')]):
            self.assertEqual(self.callback()["status"], "connected")
        self.assertEqual([value for value in self.events if value.startswith(("claim:", "capture:")) or value == "adopt"],
            ["claim:code", "capture:code", "claim:identity", "capture:identity", "adopt"])
        before = list(self.events)
        with patch.object(transport, "send", side_effect=AssertionError("callback replay contacted provider")):
            with self.assertRaises(accounts.AccountUnavailable):
                self.callback()
        self.assertNotIn("wire", self.events[len(before):])

    def test_partial_valid_json_retained_but_never_classified(self):
        raw = wire(self.token()).replace(b"Content-Length: " + str(len(self.token())).encode(), b"Content-Length: 9999")
        with self.responses([raw]), patch.object(protocol, "classify_token_response",
                side_effect=AssertionError("partial response was classified")):
            self.assertEqual(self.callback()["status"], "uncertain")
        self.assertFalse(self.captures[0].complete)
        self.assertIn(CANARY.encode(), self.captures[0].wire_prefix)
        self.assertNotIn("claim:identity", self.events)

    def test_failed_capture_commit_does_not_classify_or_send_identity(self):
        def fail(*_args):
            raise RuntimeError(CANARY)
        self.store.capture = fail
        with self.responses([wire(self.token())]), patch.object(protocol, "classify_token_response",
                side_effect=AssertionError("unretained response was classified")):
            with self.assertRaises(accounts.AccountUnavailable) as caught:
                self.callback()
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertEqual(self.events.count("wire"), 1)
        self.assertIn("hold", self.events)

    def test_interruption_capture_is_retained_and_held_without_classification(self):
        stream = Socket(wire(self.token()).replace(
            b"Content-Length: " + str(len(self.token())).encode(), b"Content-Length: 9999"))
        original = stream.recv
        def interrupted(size):
            if stream.raw:
                return original(size)
            raise KeyboardInterrupt(CANARY)
        stream.recv = interrupted
        with patch.object(transport, "_connect", return_value=stream), patch.object(
                protocol, "classify_token_response", side_effect=AssertionError("interruption classified")):
            with self.assertRaises(accounts.AccountUnavailable) as caught:
                self.callback()
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertTrue(stream.closed)
        self.assertEqual(len(self.captures), 1)
        self.assertFalse(self.captures[0].complete)
        self.assertIn(CANARY.encode(), self.captures[0].wire_prefix)
        self.assertIn("hold", self.events)
        self.assertNotIn("claim:identity", self.events)

    def test_identity_uncertainty_keeps_token_work_and_never_adopts(self):
        with self.responses([wire(self.token()), wire(b'{"data":{"id":"not-numeric"}}')]):
            self.assertEqual(self.callback()["status"], "uncertain")
        self.assertEqual(len(self.captures), 2)
        self.assertNotIn("adopt", self.events)

    def test_provider_denial_has_no_exchange_and_malformed_callback_does_not_consume(self):
        self.denied = True
        with patch.object(transport, "send", side_effect=AssertionError("denial contacted provider")):
            self.assertEqual(self.callback(code=None, error="access_denied")["status"], "denied")
        self.assertNotIn("claim:code", self.events)
        self.used = False
        with self.assertRaises(accounts.AccountUnavailable):
            self.callback(code="code", error="access_denied")
        self.assertFalse(self.used)

    def test_post_capture_expiry_holds_without_identity(self):
        original = self.store.capture
        clock = [100.0]
        def capture(*args):
            original(*args)
            clock[0] += 41
        self.store.capture = capture
        with patch.object(accounts.time, "monotonic", side_effect=lambda: clock[0]), self.responses([wire(self.token())]):
            with self.assertRaises(accounts.AccountUnavailable):
                self.callback()
        self.assertEqual(len(self.captures), 1)
        self.assertNotIn("claim:identity", self.events)

    def disconnect_fixture(self):
        tokens = [{"token_type_hint": "access_token", "token": "old-" + CANARY},
            {"token_type_hint": "access_token", "token": CANARY},
            {"token_type_hint": "refresh_token", "token": "refresh-" + CANARY}]
        self.store.fence_disconnect = lambda *_args, **_kwargs: {
            "work_id": OP, "cleanup_tokens": tokens}
        self.store.materialize_disconnect = lambda *_: self.events.append("materialized")
        self.store.finish_cleanup = lambda *_args, **kwargs: (
            self.assertEqual(len(kwargs["receipts"]), 3) or operation("disconnected", kind="disconnect"))
        return {"operation_id": OP, "credential_id": CREDENTIAL,
            "expected_revision": 1, "expected_credential_generation": 1,
            "expected_policy_hash": "sha256:" + "a" * 64, "review_digest": "sha256:" + "b" * 64}

    def test_disconnect_covers_retained_superseded_tokens_after_local_materialization(self):
        payload = self.disconnect_fixture()
        with self.responses([wire(b""), wire(b""), wire(b"")]):
            result = accounts.disconnect(payload, ACTOR)
        self.assertEqual(result["status"], "disconnected")
        self.assertEqual(self.events.count("claim:revoke"), 3)
        self.assertEqual(self.events.count("capture:revoke"), 3)
        self.assertLess(self.events.index("materialized"), self.events.index("wire"))
        self.assertIn(b"old-" + CANARY.encode(), self.captures[0].request.body)

    def test_unmaterialized_disconnect_never_contacts_provider(self):
        payload = self.disconnect_fixture()
        def refused(*_args):
            raise RuntimeError(CANARY)
        self.store.materialize_disconnect = refused
        with patch.object(transport, "send", side_effect=AssertionError("unmaterialized fence dispatched")):
            result = accounts.disconnect(payload, ACTOR)
        self.assertEqual(result["status"], "uncertain")
        self.assertNotIn("claim:revoke", self.events)

    def test_review_projection_rejects_secret_extra_unsorted_and_wrong_scope(self):
        review = {"schema": accounts.REVIEW_SCHEMA, "credential_id": CREDENTIAL,
            "expected_revision": 1, "expected_credential_generation": 1,
            "expected_policy_hash": "sha256:" + "a" * 64, "review_digest": "sha256:" + "b" * 64,
            "affected_credential_ids": [CREDENTIAL], "affected_rule_ids": []}
        self.assertEqual(accounts.validate_public_disconnect_review(review), review)
        for change in ({"secret": CANARY}, {"expected_revision": True},
                {"affected_credential_ids": []}, {"affected_rule_ids": [CREDENTIAL, OP]},
                {"affected_rule_ids": [OP, OP]}):
            with self.subTest(change=tuple(change)), self.assertRaises(accounts.AccountUnavailable):
                accounts.validate_public_disconnect_review({**review, **change})

    def test_operation_projection_cannot_expose_private_fields_or_unbounded_reasons(self):
        self.assertEqual(accounts._public(operation()), operation())
        for change in ({"token": CANARY}, {"reason": CANARY}, {"status": "retry"},
                {"expires_at_epoch_ms": None}, {"credential_id": "unknown"}):
            with self.subTest(change=tuple(change)), self.assertRaises((accounts.AccountUnavailable, ValueError)):
                accounts._public({**operation(), **change})


if __name__ == "__main__":
    unittest.main(verbosity=2)
