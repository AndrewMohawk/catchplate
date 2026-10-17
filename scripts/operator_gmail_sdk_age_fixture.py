"""Closed 31-arrival age-policy profile of the existing Gmail SDK receiver.

No control/reset endpoint, query rewriting, cached evidence or provider access.
The original receiver still owns OAuth, token generations and response hashes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
import time

from scripts import operator_gmail_sdk_fixture as sdk

SCHEMA = "catchplate.privateGmailAgeObservations/v1"
DAYS = 1
DAY_MS = 86400000
PROBE_QUERY = "fields=id%2CinternalDate&format=metadata"
PHASES = ("unrestricted", "recent", "refreshed", "old-list", "missing-list",
    "future-list", "mismatch-list", "old-get", "missing-get")
COUNTS = (4, 6, 6, 3, 2, 2, 2, 3, 3)
PROBE_HEADERS = {"host": "gmail.googleapis.com", "accept": "application/json", "accept-encoding": "identity"}
CLIENT_HEADERS = sdk.profiles.provider_headers("python:list_page_1")


def plan(anchor):
    sdk.base.require(type(anchor) is int and anchor > 3 * DAY_MS)
    rows = []
    for phase in PHASES:
        generation = 1 if phase in {"unrestricted", "recent"} else 2
        pages = (1, 2) if phase in {"unrestricted", "recent", "refreshed"} else (1,)
        for page in pages:
            ident = sdk.MESSAGE_IDS[page - 1]
            body = json.loads(sdk.TARGETS["list_page_" + str(page)]["body"])
            if phase == "old-list":
                body["messages"].append({"id": sdk.MESSAGE_IDS[1], "threadId": sdk.THREAD_IDS[1]})
            rows.append({"phase": phase, "kind": "list", "page": page, "id": None,
                "generation": generation, "body": body})
            if phase != "unrestricted":
                for index, item in enumerate(body["messages"]):
                    metadata = {"id": item["id"], "internalDate": str(anchor - 3600000)}
                    if phase == "old-list" and index == 1:
                        metadata["internalDate"] = str(anchor - 2 * DAY_MS)
                    elif phase == "missing-list":
                        metadata.pop("internalDate")
                    elif phase == "future-list":
                        metadata["internalDate"] = str(anchor + DAY_MS)
                    elif phase == "mismatch-list":
                        metadata["id"] = "different-message"
                    rows.append({"phase": phase, "kind": "probe", "page": page, "id": item["id"],
                        "generation": generation, "body": metadata})
            if phase.endswith("-list"):
                continue
            body = json.loads(sdk.TARGETS["message_metadata_" + str(page)]["body"])
            if phase != "unrestricted":
                body["internalDate"] = str(anchor - (2 * DAY_MS if phase == "old-get" else 3600000))
            if phase == "missing-get":
                body.pop("internalDate")
            rows.append({"phase": phase, "kind": "get", "page": page, "id": ident,
                "generation": generation, "body": body})
    sdk.base.require(len(rows) == 31)
    return rows


def target(row, after=None):
    path = sdk.base.GMAIL_PATH + ("/" + row["id"] if row["id"] else "")
    if row["kind"] == "probe":
        query = PROBE_QUERY
    elif row["kind"] == "get":
        query = sdk.profiles.QUERIES["python"][1]
    else:
        query = "maxResults=5&labelIds=INBOX"
        if row["phase"] != "unrestricted":
            sdk.base.require(type(after) is int and after > 0)
            query += "&q=after%3A" + str(after)
        if row["page"] == 2:
            query += "&pageToken=next%2Bpage+%2F%3D"
        query += "&alt=json"
    return path, query


class GmailAgeFixture(sdk.GmailSdkFixture):
    def __init__(self, work_dir=sdk.base.PKI):
        super().__init__(work_dir, sdk_pair=True)
        self.anchor = time.time_ns() // 1000000
        self.plan = plan(self.anchor)
        self.after = {}

    def note_arrival(self, handler):
        self._sdk_request.attempt = None
        if not sdk._is_gmail_arrival(handler):
            return
        self._expire()
        with self._lock:
            self._counts["google"]["resource_attempts"] += 1
            ordinal = self._counts["google"]["resource_attempts"]
            self._record_locked("google", "resource_received", attempt=ordinal)
            if ordinal > len(self.plan):
                return
            spec = self.plan[ordinal - 1]
            phase = spec["phase"]
            match = re.fullmatch(r"/gmail/v1/users/me/messages\?maxResults=5&labelIds=INBOX&q=after%3A([1-9][0-9]{8,11})&alt=json", handler.path)
            if spec["kind"] == "list" and spec["page"] == 1 and phase != "unrestricted" and match:
                after = int(match[1])
                minimum = (self.anchor - DAY_MS + 999) // 1000
                if minimum <= after <= minimum + 300:
                    self.after[phase] = after
            ready = phase == "unrestricted" or phase in self.after
            path, query = target(spec, self.after.get(phase)) if ready else (None, None)
            headers = PROBE_HEADERS if spec["kind"] == "probe" else CLIENT_HEADERS
            names = [name.lower() for name, _ in handler.headers.items()]
            matches = (len(names) == len(set(names)) and set(names) <= set(headers) | {"authorization", "connection", "content-length"}
                and all(handler.headers.get_all(name, []) == [value] for name, value in headers.items())
                and handler.headers.get_all("Connection", []) in ([], ["close"]))
            framing = handler.headers.get_all("Content-Length", []) in ([], ["0"]) and not handler.headers.get_all("Transfer-Encoding", [])
            generation, token_state = self._token_observation_locked(handler)
            recognized = ready and handler.command == "GET" and handler.path == path + "?" + query
            row = {"ordinal": ordinal, "case": phase + ":" + spec["kind"] + ":" + str(spec["page"]),
                "kind": spec["kind"], "phase": phase, "method": "GET" if handler.command == "GET" else "OTHER",
                "path": path if recognized else None, "rawQuery": query if recognized else None,
                "hostMatches": handler.headers.get_all("Host", []) == ["gmail.googleapis.com"],
                "headersMatch": matches, "framingMatch": framing, "requestHeaders": dict(headers) if matches else None,
                "authorized": False, "status": None, "tokenGeneration": generation, "tokenState": token_state,
                "timestampEpochMs": time.time_ns() // 1000000, "responseBodySha256": None, "responseBodyBytes": None,
                "responseFraming": None}
            self._sdk_attempts.append(row)
            self._sdk_request.attempt = row

    def _handle_get(self, handler):
        if not sdk._is_gmail_arrival(handler):
            return super()._handle_get(handler)
        admitted = self._admit(handler)
        if admitted is None:
            return
        row = getattr(self._sdk_request, "attempt", None)
        if row is None or not all((row["path"], row["hostMatches"], row["headersMatch"], row["framingMatch"])):
            return self._send_json(handler, 400, {"error": "fixture_age_request_refused"})
        spec = self.plan[row["ordinal"] - 1]
        if self._authorized_grant(handler, provider="google", required_scope="https://www.googleapis.com/auth/gmail.readonly",
                operation="gmail.messages.list" if spec["kind"] == "list" else "gmail.message.get") is None:
            return
        self._send_json(handler, 200, spec["body"])

    def _send_json(self, handler, status, payload):
        row = getattr(self._sdk_request, "attempt", None)
        chunked = row is not None and (row["phase"], row["kind"], row["ordinal"]) == ("recent", "probe", 6) and status == 200
        if row is not None:
            row["responseFraming"] = "chunked" if chunked else "content-length"
        if not chunked:
            return super()._send_json(handler, status, payload)
        # One existing positive probe exercises ordinary chunked decoding. No
        # compression, trailers, Content-Length, additional call or payload.
        body = sdk._json_bytes(payload)
        with self._lock:
            row.update(status=status, responseBodySha256="sha256:" + hashlib.sha256(body).hexdigest(), responseBodyBytes=len(body))
        handler.send_response(status)
        for name, value in (("Content-Type", "application/json"), ("Cache-Control", "no-store"),
                ("Transfer-Encoding", "chunked"), ("Connection", "close")):
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n0\r\n\r\n")

    def observations(self):
        with self._lock:
            value = sdk.base.GoogleFixture.observations(self)
            value["gmailAge"] = {"schema": SCHEMA, "maxAttempts": 32, "anchorEpochMs": self.anchor,
                "afterEpochSeconds": dict(self.after), "attempts": deepcopy(self._sdk_attempts)}
            self.assert_no_token_values(json.dumps(value))
            return value
