#!/usr/bin/env python3
"""Closed X HTTP shapes and callback transport controls, not lifecycle proof."""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import HTTPException
from starlette.requests import Request
from serverware import operator_x_accounts_api as api, operator_x_accounts as service
from serverware import operator_x_oauth_profile as profiles, operator_x_oauth_protocol as protocol
from serverware.operator_x_account_inputs import StartInput, DisconnectInput

OPERATION = "20000000-0000-4000-8000-000000000001"
CREDENTIAL = "20000000-0000-4000-8000-000000000002"
STATE = "S" * 43
NONCE = "N" * 43
ORIGIN = "https://console.example.com"
PRIVATE = "synthetic-private-X-code-never-in-response"
PROFILE = profiles.build_profile(client_id="synthetic-X-app", public_origin=ORIGIN)


def request(query=None, *, headers=(), body=b""):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    raw = urlencode(query or {"state": STATE, "code": PRIVATE}).encode()
    return Request({"type": "http", "http_version": "1.1", "method": "GET",
        "scheme": "https", "server": ("console.example.com", 443), "client": ("127.0.0.1", 1),
        "path": api.CALLBACK, "raw_path": api.CALLBACK.encode(), "query_string": raw,
        "headers": [(name.encode(), value.encode()) for name, value in headers]}, receive)


def operation(**changes):
    return {"schema": service.OPERATION_SCHEMA, "operation_id": OPERATION, "kind": "consent",
        "status": "connected", "credential_id": CREDENTIAL, "reason": None,
        "created_at": "2026-10-12T00:00:00+00:00", "expires_at_epoch_ms": 1791849999000, **changes}


class XAccountApiTests(unittest.TestCase):
    def test_strict_inputs(self):
        start = {"operation_id": OPERATION, "name": "My X account", "expected_revision": 2,
            "expected_policy_hash": "sha256:" + "a" * 64}
        self.assertEqual(StartInput.model_validate(start).operation_id, OPERATION)
        for extra in ({"secret": PRIVATE}, {"expected_revision": True}, {"operation_id": OPERATION.upper()}):
            # Decimal-only UUID has no case variant; use an actual uppercase hex digit.
            if extra.get("operation_id") == OPERATION:
                extra = {"operation_id": "A0000000-0000-4000-8000-000000000001"}
            with self.assertRaises(ValueError):
                StartInput.model_validate({**start, **extra})
        disconnect = {key: value for key, value in start.items() if key != "name"}
        disconnect.update(credential_id=CREDENTIAL, expected_credential_generation=1,
            review_digest="sha256:" + "b" * 64)
        self.assertEqual(DisconnectInput.model_validate(disconnect).credential_id, CREDENTIAL)
        with self.assertRaises(ValueError):
            DisconnectInput.model_validate({**disconnect, "expected_credential_generation": False})

    def test_closed_callback_query(self):
        self.assertEqual(api._callback_query(request())["code"], PRIVATE)
        for query in ({"state": STATE, "code": PRIVATE, "error": "access_denied"},
                {"state": STATE, "code": PRIVATE, "extra": "x"}, {"state": STATE},
                {"state": STATE, "code": ""}, {"state": STATE, "code": "bad\nvalue"}):
            with self.assertRaises(ValueError):
                api._callback_query(request(query))
        duplicate = request()
        duplicate.scope["query_string"] += b"&state=" + STATE.encode()
        with self.assertRaises(ValueError):
            api._callback_query(duplicate)
        malformed = request()
        malformed.scope["query_string"] += b"%ZZ"
        with self.assertRaises(ValueError):
            api._callback_query(malformed)

    def test_exact_one_browser_cookie(self):
        cookie = api._COOKIE_PREFIX + STATE + "=" + NONCE
        self.assertEqual(api._callback_nonce(request(headers=[("cookie", cookie)]), STATE)[1], NONCE)
        for headers in ([], [("cookie", cookie + "; " + cookie)], [("cookie", cookie), ("cookie", cookie)],
                [("cookie", cookie + "x")], [("cookie", "wrong=" + NONCE)]):
            with self.assertRaises(ValueError):
                api._callback_nonce(request(headers=headers), STATE)

    def test_start_cookie_and_exact_authorize_target(self):
        value = {"schema": service.CONSENT_SCHEMA, "operation_id": OPERATION, "status": "consent_pending",
            "authorization_url": protocol.authorization_url(PROFILE, state=STATE, code_verifier="V" * 43),
            "state": STATE, "expires_at_epoch_ms": time.time_ns() // 1_000_000 + 590000,
            "profile_binding_digest": PROFILE.binding_digest}
        with patch.object(api, "time", wraps=time), patch("serverware.operator_x_admission.public_origin", return_value=ORIGIN):
            response = api._start_response(value, NONCE)
            cookie = response.headers["set-cookie"]
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Secure", cookie)
            self.assertIn("SameSite=lax", cookie)
            self.assertIn("Path=/", cookie)
            self.assertNotIn("Domain=", cookie)
            self.assertNotIn(NONCE.encode(), response.body)
            for bad in ({**value, "secret": PRIVATE},
                    {**value, "authorization_url": value["authorization_url"].replace("https://x.com/", "https://other.example/")},
                    {**value, "expires_at_epoch_ms": time.time_ns() // 1_000_000 + 700000}):
                with self.assertRaises(ValueError):
                    api._start_response(bad, NONCE)

    def test_operation_projection_rejects_private_extras(self):
        self.assertEqual(api._operation(operation())["credential_id"], CREDENTIAL)
        for bad in (operation(secret=PRIVATE), operation(reason=PRIVATE), operation(status="approved"),
                operation(expires_at_epoch_ms=True)):
            with self.assertRaises((ValueError, TypeError)):
                api._operation(bad)

    def test_callback_fixed_html_no_provider_reflection(self):
        cookie = api._COOKIE_PREFIX + STATE + "=" + NONCE
        with ExitStack() as stack:
            stack.enter_context(patch.object(api.admission, "_profile"))
            stack.enter_context(patch.object(api, "_enabled"))
            completed = stack.enter_context(patch.object(service, "complete_callback", return_value=operation()))
            response = api.callback_response(request(headers=[("cookie", cookie)]))
            self.assertEqual(response.status_code, 200)
            self.assertIn(("serverware_x_operation=" + OPERATION).encode(), response.body)
            self.assertNotIn(PRIVATE.encode(), response.body)
            self.assertNotIn(STATE.encode(), response.body)
            self.assertIn("default-src 'none'", response.headers["content-security-policy"])
            self.assertEqual(completed.call_args.kwargs["browser_nonce"], NONCE)
            completed.side_effect = RuntimeError(PRIVATE)
            response = api.callback_response(request(headers=[("cookie", cookie)]))
            self.assertEqual(response.status_code, 409)
            self.assertNotIn(PRIVATE.encode(), response.body)

    def test_callback_body_and_framing_refused_before_owner(self):
        with patch.object(api.admission, "_profile"), patch.object(api, "_enabled"), \
                patch.object(service, "complete_callback") as owner:
            for incoming in (request(body=b"undeclared"), request(headers=[("content-length", "1")]),
                    request(headers=[("transfer-encoding", "chunked")])):
                with self.assertRaises(HTTPException) as caught:
                    asyncio.run(api.callback(incoming))
                self.assertEqual(caught.exception.status_code, 400)
            owner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
