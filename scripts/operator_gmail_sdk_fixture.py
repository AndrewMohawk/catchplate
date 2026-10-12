"""Opt-in, finite receiver for the unmodified official Go Gmail SDK example.

OAuth, PKCE, the original real 90-second access expiry, rotated refresh, TLS and
network isolation are inherited unchanged. This fixture does not rewrite SDK
requests. Known public request shapes are committed independently; unexpected
targets/header values and all authentication values are never echoed or hashed.
Response status/commitments describe an attempted response, not client receipt.
Never run this fixture on the host or against real Google accounts.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import signal
import threading
import time

from scripts import operator_google_fixture as base
from scripts import operator_gmail_sdk_profiles as profiles


GO_VERSION = "1.26.9"
SDK_VERSION = "0.264.0"
SDK_HEADERS = {"user-agent": "google-api-go-client/0.5",
    "x-goog-api-client": "gl-go/1.26.9 gdcl/0.264.0"}
# The SDK sends no Accept. The unchanged gate's reqwest 0.12.28 ClientBuilder
# adds this default upstream. It MUST NOT be added to the SDK canonical-v3
# request oracle merely because it is observed at the provider boundary.
PROVIDER_HEADERS = {"accept": "*/*", "host": "gmail.googleapis.com", **SDK_HEADERS}
MESSAGE_IDS = ("msg_1", "msg-2")
THREAD_IDS = ("thread_1", "thread-2")
PAGE_TOKEN = "next+page /="
SDK_SCHEMA = "serverware.privateGmailSdkObservations/v1"
REQUEST_SCHEMA = "serverware.privateGmailSdkRequest/v1"
MAX_ATTEMPTS = 32
EMPTY_SHA256 = "sha256:" + hashlib.sha256(b"").hexdigest()
READY_MESSAGE = "Isolated synthetic Gmail SDK fixture ready; no provider values emitted."


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _target(path, raw_query, payload):
    return {"path": path, "raw_query": raw_query, "body": _json_bytes(payload)}


# Deliberate literal query vectors, not urlencode() or the SDK's implementation.
# Order and '+' versus percent escapes are part of the independent wire oracle.
_LIST_QUERY = "alt=json&labelIds=INBOX&maxResults=5&prettyPrint=false"
_NEXT_QUERY = "alt=json&labelIds=INBOX&maxResults=5&pageToken=next%2Bpage+%2F%3D&prettyPrint=false"
_METADATA_QUERY = "alt=json&format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&prettyPrint=false"
TARGETS = {
    "list_page_1": _target(base.GMAIL_PATH, _LIST_QUERY, {
        "messages": [{"id": MESSAGE_IDS[0], "threadId": THREAD_IDS[0]}],
        "nextPageToken": PAGE_TOKEN, "resultSizeEstimate": 2}),
    "message_metadata_1": _target(base.GMAIL_PATH + "/" + MESSAGE_IDS[0], _METADATA_QUERY, {
        "id": MESSAGE_IDS[0], "threadId": THREAD_IDS[0], "labelIds": ["INBOX"],
        "internalDate": "1767225600000", "sizeEstimate": 128,
        "payload": {"headers": [{"name": "From", "value": "fixture-sender@example.com"},
            {"name": "Subject", "value": "Synthetic SDK fixture one"},
            {"name": "Date", "value": "Thu, 01 Jan 2026 00:00:00 +0000"}]}}),
    "list_page_2": _target(base.GMAIL_PATH, _NEXT_QUERY, {
        "messages": [{"id": MESSAGE_IDS[1], "threadId": THREAD_IDS[1]}], "resultSizeEstimate": 2}),
    "message_metadata_2": _target(base.GMAIL_PATH + "/" + MESSAGE_IDS[1], _METADATA_QUERY, {
        "id": MESSAGE_IDS[1], "threadId": THREAD_IDS[1], "labelIds": ["INBOX"],
        "internalDate": "1767312000000", "sizeEstimate": 129,
        "payload": {"headers": [{"name": "From", "value": "fixture-sender@example.com"},
            {"name": "Subject", "value": "Synthetic SDK fixture two"},
            {"name": "Date", "value": "Fri, 02 Jan 2026 00:00:00 +0000"}]}}),
}
CASES = tuple(TARGETS)
ROW_KEYS = frozenset(("ordinal", "case", "method", "path", "rawQuery", "hostMatches",
    "headersMatch", "framingMatch", "requestHeaders", "requestBodySha256", "requestBodyBytes",
    "requestCommitment", "authorized", "status", "tokenGeneration", "tokenState", "timestampEpochMs",
    "responseBodySha256", "responseBodyBytes"))


def selected_targets(sdk_pair=False):
    base.require(type(sdk_pair) is bool)
    return profiles.targets(TARGETS) if sdk_pair else TARGETS


def recognized_case(target, sdk_pair=False):
    return next((name for name, spec in selected_targets(sdk_pair).items()
        if target == spec["path"] + "?" + spec["raw_query"]), None)


def request_commitment(case, sdk_pair=False):
    """Provider-boundary public commitment, NOT the gate authorization digest."""
    spec = selected_targets(sdk_pair)[case]
    public = {"schema": REQUEST_SCHEMA, "method": "GET", "authority": "gmail.googleapis.com",
        "path": spec["path"], "rawQuery": spec["raw_query"],
        "headers": profiles.provider_headers(case) if sdk_pair else PROVIDER_HEADERS,
        "bodySha256": EMPTY_SHA256, "bodyBytes": 0}
    return "sha256:" + hashlib.sha256(_json_bytes(public)).hexdigest()


def _is_gmail_arrival(handler):
    hosts = handler.headers.get_all("Host", [])
    is_gmail_host = any(value in ("gmail.googleapis.com", "gmail.googleapis.com:443") for value in hosts)
    if (hosts == ["gmail.googleapis.com"] or hosts == ["gmail.googleapis.com:443"]):
        if handler.command == "GET" and handler.path == base.OBSERVATIONS_PATH:
            return False
    return is_gmail_host or handler.path.startswith("/gmail")


def _header_matches(handler, case=None, sdk_pair=False):
    if sdk_pair and case is None:
        return False
    expected = profiles.provider_headers(case) if sdk_pair else PROVIDER_HEADERS
    names = [name.lower() for name, _ in handler.headers.items()]
    allowed = set(expected) | {"authorization", "connection", "content-length"}
    return (len(names) == len(set(names)) and set(names) <= allowed
        and all(handler.headers.get_all(name, []) == [value] for name, value in expected.items())
        and handler.headers.get_all("Connection", []) in ([], ["close"]))


class GmailSdkFixture(base.GoogleFixture):
    def __init__(self, work_dir=base.PKI, *, sdk_pair=False):
        super().__init__(work_dir)
        base.require(type(sdk_pair) is bool)
        self.sdk_pair = sdk_pair
        self._sdk_attempts = []
        self._sdk_request = threading.local()

    def _token_observation_locked(self, handler):
        values = handler.headers.get_all("Authorization", [])
        if not values:
            return None, "missing"
        if len(values) != 1:
            return None, "ambiguous"
        value = values[0]
        if len(value) > 1024 or not value.startswith("Bearer ") or value.count(" ") != 1:
            return None, "unknown"
        token = value.removeprefix("Bearer ")
        expiry, reference = self._expiry.get(token), self._access_tokens.get(token)
        if expiry is None or reference is None:
            return None, "unknown"
        if time.monotonic() >= expiry[0]:
            return expiry[2], "expired"
        grant = self._grants.get(reference.grant_id)
        return expiry[2], "active" if reference.active and grant is not None and grant.active else "inactive"

    def note_arrival(self, handler):
        self._sdk_request.attempt = None
        if not _is_gmail_arrival(handler):
            return
        # Count before method, target, header and credential admission. Rows are
        # capped, while the counter keeps exposing excess arrivals; no reset API.
        self._expire()
        case = recognized_case(handler.path, self.sdk_pair)
        spec = selected_targets(self.sdk_pair).get(case)
        method = handler.command if handler.command in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} else "OTHER"
        host_matches = handler.headers.get_all("Host", []) == ["gmail.googleapis.com"]
        headers_match = _header_matches(handler, case, self.sdk_pair)
        framing_match = (handler.headers.get_all("Content-Length", []) in ([], ["0"])
            and not handler.headers.get_all("Transfer-Encoding", []))
        with self._lock:
            self._counts["google"]["resource_attempts"] += 1
            ordinal = self._counts["google"]["resource_attempts"]
            self._record_locked("google", "resource_received", attempt=ordinal)
            if ordinal > MAX_ATTEMPTS:
                return
            generation, token_state = self._token_observation_locked(handler)
            attempt = {"ordinal": ordinal, "case": case, "method": method,
                "path": spec["path"] if spec else None, "rawQuery": spec["raw_query"] if spec else None,
                "hostMatches": host_matches, "headersMatch": headers_match, "framingMatch": framing_match,
                "requestHeaders": (profiles.provider_headers(case) if self.sdk_pair else dict(PROVIDER_HEADERS)) if headers_match else None,
                # Empty body is the HTTP framing claim, not a socket EOF claim.
                "requestBodySha256": EMPTY_SHA256 if framing_match else None,
                "requestBodyBytes": 0 if framing_match else None,
                "requestCommitment": request_commitment(case, self.sdk_pair) if case and method == "GET"
                    and host_matches and headers_match and framing_match else None,
                "authorized": False, "status": None, "tokenGeneration": generation, "tokenState": token_state,
                "timestampEpochMs": time.time_ns() // 1_000_000,
                "responseBodySha256": None, "responseBodyBytes": None}
            self._sdk_attempts.append(attempt)
            self._sdk_request.attempt = attempt

    def _record_locked(self, provider, event_type, **details):
        if event_type == "resource_authorized":
            attempt = getattr(self._sdk_request, "attempt", None)
            if attempt is not None:
                attempt["authorized"] = True
                attempt["tokenGeneration"] = self._request_generation.value
        super()._record_locked(provider, event_type, **details)

    def _send_json(self, handler, status, payload):
        attempt = getattr(self._sdk_request, "attempt", None)
        if attempt is not None:
            body = _json_bytes(payload)
            with self._lock:
                attempt["status"] = status
                attempt["responseBodySha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
                attempt["responseBodyBytes"] = len(body)
        super()._send_json(handler, status, payload)

    def _handle_get(self, handler):
        if not _is_gmail_arrival(handler):
            return super()._handle_get(handler)
        admitted = self._admit(handler)
        if admitted is None:
            return
        host, _ = admitted
        if host != "gmail.googleapis.com":
            self._send_json(handler, 404, {"error": "fixture_route_refused"})
            return
        attempt = getattr(self._sdk_request, "attempt", None)
        if attempt is None:
            self._send_json(handler, 503, {"error": "fixture_attempt_bound"})
            return
        if not all((attempt["case"], attempt["hostMatches"], attempt["headersMatch"], attempt["framingMatch"])):
            self._send_json(handler, 400, {"error": "fixture_sdk_request_refused"})
            return
        case = attempt["case"]
        operation = "gmail.messages.list" if case.rsplit(":", 1)[-1].startswith("list_") else "gmail.message.get"
        if self._authorized_grant(handler, provider="google",
                required_scope="https://www.googleapis.com/auth/gmail.readonly", operation=operation) is None:
            return
        self._send_json(handler, 200, json.loads(selected_targets(self.sdk_pair)[case]["body"]))

    def observations(self):
        with self._lock:
            result = super().observations()
            result["gmailSdk"] = {"schema": profiles.OBSERVATION_SCHEMA if self.sdk_pair else SDK_SCHEMA, "maxAttempts": MAX_ATTEMPTS,
                "attempts": deepcopy(self._sdk_attempts)}
            self.assert_no_token_values(json.dumps(result))
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    parser.add_argument("--sdk-pair", action="store_true")
    args = parser.parse_args()
    base.require(120 <= args.lifetime_seconds <= 300)
    base.assert_isolated_network()
    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    fixture = GmailSdkFixture(sdk_pair=args.sdk_pair)
    front = base._BoundedServer(("127.0.0.1", 443), base._ControlFront, base.server_context(base.PKI))
    thread = threading.Thread(target=front.serve_forever, daemon=True)
    try:
        fixture.start()
        thread.start()
        print(READY_MESSAGE, flush=True)
        stopped.wait(args.lifetime_seconds)
    finally:
        fixture.close()
        if thread.is_alive():
            front.shutdown()
        front.server_close()
        thread.join(timeout=6) if thread.ident else None


if __name__ == "__main__":
    main()
