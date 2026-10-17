"""Finite synthetic Gmail inbox job on the existing isolated Google transport.

This is a separate opt-in fixture, not a provider implementation. Exact known
request targets make rewriting of ordinary client query bytes observable. OAuth,
PKCE, real 90-second access expiry, rotated refresh and network isolation remain
owned by the unchanged Google fixture. No caller input or token value is logged.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import signal
import threading
import time
from urllib.parse import urlencode

from scripts import operator_google_fixture as base


MESSAGE_IDS = ("18f0000000000001", "18f0000000000002")
THREAD_IDS = ("18e0000000000001", "18e0000000000002")
PAGE_TOKEN = "fixture-page-2+/="
LIST_PARAMS = (("maxResults", "1"), ("labelIds", "INBOX"), ("labelIds", "UNREAD"),
    ("q", "subject:Catchplate fixture"), ("prettyPrint", "false"))
FULL_PARAMS = (("format", "full"), ("prettyPrint", "false"))
METADATA_PARAMS = (("metadataHeaders", "Subject"), ("format", "metadata"),
    ("metadataHeaders", "From"), ("prettyPrint", "false"))
MAX_ATTEMPTS = 16
GMAIL_PREFIX = "/gmail/v1/"
JOB_SCHEMA = "catchplate.privateGmailJobObservations/v1"


def _target(path, params, payload):
    return {"path": path, "params": params, "raw_query": urlencode(params),
        "body": json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")}


TARGETS = {
    "list_page_1": _target(base.GMAIL_PATH, LIST_PARAMS, {
        "messages": [{"id": MESSAGE_IDS[0], "threadId": THREAD_IDS[0]}],
        "nextPageToken": PAGE_TOKEN, "resultSizeEstimate": 2}),
    "list_page_2": _target(base.GMAIL_PATH, (*LIST_PARAMS, ("pageToken", PAGE_TOKEN)), {
        "messages": [{"id": MESSAGE_IDS[1], "threadId": THREAD_IDS[1]}], "resultSizeEstimate": 2}),
    "message_full": _target(base.GMAIL_PATH + "/" + MESSAGE_IDS[0], FULL_PARAMS, {
        "id": MESSAGE_IDS[0], "threadId": THREAD_IDS[0], "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Synthetic fixture message one.", "internalDate": "1767225600000", "sizeEstimate": 128,
        "payload": {"mimeType": "text/plain", "headers": [
            {"name": "Subject", "value": "Catchplate fixture one"},
            {"name": "From", "value": "fixture-sender@example.com"},
            {"name": "To", "value": "fixture-recipient@example.com"}],
            "body": {"size": 30, "data": "U3ludGhldGljIGZpeHR1cmUgbWVzc2FnZSBvbmUu"}}}),
    "message_metadata": _target(base.GMAIL_PATH + "/" + MESSAGE_IDS[1], METADATA_PARAMS, {
        "id": MESSAGE_IDS[1], "threadId": THREAD_IDS[1], "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Synthetic fixture message two.", "internalDate": "1767312000000", "sizeEstimate": 129,
        "payload": {"mimeType": "text/plain", "headers": [
            {"name": "Subject", "value": "Catchplate fixture two"},
            {"name": "From", "value": "fixture-sender@example.com"}]}}),
}


def recognized_case(target):
    """Finite allowlist: observations never echo arbitrary path/query material."""
    return next((name for name, spec in TARGETS.items()
        if target == spec["path"] + "?" + spec["raw_query"]), None)


class GmailJobFixture(base.GoogleFixture):
    def __init__(self, work_dir=base.PKI):
        super().__init__(work_dir)
        self._job_attempts = []
        self._job_request = threading.local()

    def note_arrival(self, handler):
        self._job_request.attempt = None
        # Include unsupported paths/methods/hosts: an accidental provider
        # dispatch must not disappear behind the resource authorization count.
        if not handler.path.startswith(GMAIL_PREFIX):
            return
        case = recognized_case(handler.path)
        spec = TARGETS[case] if case is not None else None
        method = getattr(handler, "command", "OTHER")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = "OTHER"
        with self._lock:
            self._counts["google"]["resource_attempts"] += 1
            ordinal = self._counts["google"]["resource_attempts"]
            self._record_locked("google", "resource_received", attempt=ordinal)
            if ordinal > MAX_ATTEMPTS:
                return
            attempt = {"ordinal": ordinal, "case": case, "method": method,
                "path": spec["path"] if spec else None, "rawQuery": spec["raw_query"] if spec else None,
                "authorized": False, "status": None, "tokenGeneration": None,
                "acceptEncodingAbsent": not handler.headers.get_all("Accept-Encoding", []),
                "timestampEpochMs": time.time_ns() // 1_000_000}
            self._job_attempts.append(attempt)
            self._job_request.attempt = attempt

    def _record_locked(self, provider, event_type, **details):
        if event_type == "resource_authorized":
            attempt = getattr(self._job_request, "attempt", None)
            if attempt is not None:
                attempt["authorized"] = True
                attempt["tokenGeneration"] = self._request_generation.value
        super()._record_locked(provider, event_type, **details)

    def _send_json(self, handler, status, payload):
        attempt = getattr(self._job_request, "attempt", None)
        if attempt is not None:
            with self._lock:
                attempt["status"] = status
        super()._send_json(handler, status, payload)

    def _handle_get(self, handler):
        if not handler.path.startswith(GMAIL_PREFIX):
            return super()._handle_get(handler)
        admitted = self._admit(handler)
        if admitted is None:
            return
        host, _ = admitted
        if host != "gmail.googleapis.com":
            self._send_json(handler, 404, {"error": "fixture_route_refused"})
            return
        attempt = getattr(self._job_request, "attempt", None)
        if attempt is None:
            self._send_json(handler, 503, {"error": "fixture_attempt_bound"})
            return
        if (handler.headers.get_all("Content-Length", []) not in ([], ["0"])
                or handler.headers.get_all("Accept-Encoding", []) or attempt["case"] is None):
            self._send_json(handler, 400, {"error": "fixture_job_request_refused"})
            return
        case = attempt["case"]
        operation = "gmail.messages.list" if case.startswith("list_") else "gmail.message.get"
        if self._authorized_grant(handler, provider="google",
                required_scope="https://www.googleapis.com/auth/gmail.readonly", operation=operation) is None:
            return
        self._send_json(handler, 200, json.loads(TARGETS[case]["body"]))

    def observations(self):
        with self._lock:
            result = super().observations()
            result["gmailJob"] = {"schema": JOB_SCHEMA, "maxAttempts": MAX_ATTEMPTS,
                "attempts": deepcopy(self._job_attempts)}
            self.assert_no_token_values(json.dumps(result))
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    base.require(120 <= args.lifetime_seconds <= 300)
    base.assert_isolated_network()
    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    fixture = GmailJobFixture()
    front = base._BoundedServer(("127.0.0.1", 443), base._ControlFront, base.server_context(base.PKI))
    thread = threading.Thread(target=front.serve_forever, daemon=True)
    try:
        fixture.start()
        thread.start()
        print("Isolated synthetic Gmail job fixture ready; no provider values emitted.", flush=True)
        stopped.wait(args.lifetime_seconds)
    finally:
        fixture.close()
        if thread.is_alive():
            front.shutdown()
        front.server_close()
        thread.join(timeout=6) if thread.ident else None


if __name__ == "__main__":
    main()
