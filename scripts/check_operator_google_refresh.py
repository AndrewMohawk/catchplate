#!/usr/bin/env python3
"""One-shot real catalog/CONNECT acceptance against isolated synthetic Google.

Never launches services, changes provider URLs, retrieves provider tokens, or
patches refresh timers. Run only inside the prepared network-none namespace.
Consent/callback use real HTTP endpoints and the actual browser-binding cookie;
this is not a rendered-browser, real-Google or production acceptance claim.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import http.client
from http.cookies import SimpleCookie
import io
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import operator_google_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, OperatorCatalogCheck, claim_fixture, features
from scripts.check_operator_demo import Endpoint, SHA256, CheckFailure, TunnelTLS, require, token_file


SCOPES = ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"]
GMAIL_ORIGIN = "https://gmail.googleapis.com"
GMAIL_AUTHORITY = "gmail.googleapis.com:443"
CALLBACK_PATH = "/api/oauth/callback/google"
MAX_HTTP_BODY = 65536
STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
CODE = re.compile(r"[A-Za-z0-9._-]{1,256}\Z")
STAGES = {"fresh": (0, 0, 0), "connected": (1, 0, 0),
          "first": (1, 0, 1), "expired": (1, 0, 1), "refreshed": (1, 1, 2)}


def read_google_marker(path):
    require(path.is_absolute() and path.resolve() == path, "explicit isolated Google marker required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400
                and info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size <= 1024,
                "isolated Google marker custody differs")
        require(json.loads(os.read(descriptor, 1025)) == fixture.MARKER,
                "isolated Google marker differs")
    finally:
        os.close(descriptor)


def closed_query(raw):
    require(isinstance(raw, str) and len(raw) <= 8192 and re.search(r"%(?![0-9A-Fa-f]{2})", raw) is None,
            "OAuth redirect query is malformed")
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=16,
                      encoding="ascii", errors="strict")
    require(len({key for key, _ in pairs}) == len(pairs), "OAuth redirect query duplicates a field")
    return dict(pairs)


def authorization_target(started):
    require(isinstance(started, dict) and started.get("provider") == "google"
            and isinstance(started.get("state"), str) and STATE.fullmatch(started["state"])
            and started.get("redirectUri") == fixture.CONTROL_ORIGIN + CALLBACK_PATH
            and sorted(started.get("scopes", [])) == SCOPES,
            "OAuth start public bindings differ")
    parsed = urlsplit(started.get("authorizationUrl", ""))
    expected = urlsplit(fixture.AUTHORIZATION_URL)
    require((parsed.scheme, parsed.netloc, parsed.path) == (expected.scheme, expected.netloc, expected.path)
            and not parsed.fragment, "OAuth authorization destination differs")
    query = closed_query(parsed.query)
    require(set(query) == {"response_type", "client_id", "redirect_uri", "scope", "state",
            "code_challenge", "code_challenge_method", "access_type", "prompt", "include_granted_scopes"}
            and query["response_type"] == "code" and query["client_id"] == fixture.CLIENT_ID
            and query["redirect_uri"] == started["redirectUri"] and query["state"] == started["state"]
            and sorted(query["scope"].split(" ")) == SCOPES and re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"])
            and query["code_challenge_method"] == "S256" and query["access_type"] == "offline"
            and query["prompt"] == "consent" and query["include_granted_scopes"] == "true",
            "OAuth consent or PKCE parameters differ")
    return parsed.path + "?" + parsed.query


def browser_cookie(headers, state):
    values = [value for key, value in headers if key.lower() == "set-cookie"]
    require(len(values) == 1 and len(values[0]) <= 2048, "OAuth browser-binding cookie missing or duplicated")
    cookies = SimpleCookie()
    cookies.load(values[0])
    name = "__Host-serverware-oauth-" + state
    require(set(cookies) == {name}, "OAuth browser-binding cookie name differs")
    value = cookies[name]
    require(STATE.fullmatch(value.value) and value["secure"] and value["httponly"]
            and value["path"] == "/" and not value["domain"] and value["samesite"].lower() == "lax",
            "OAuth browser-binding cookie attributes differ")
    return name + "=" + value.value, value.value


def callback_target(headers, state):
    locations = [value for name, value in headers if name.lower() == "location"]
    require(len(locations) == 1 and len(locations[0]) <= 8192, "OAuth consent redirect missing or duplicated")
    parsed = urlsplit(locations[0])
    require(parsed.scheme + "://" + parsed.netloc == fixture.CONTROL_ORIGIN
            and parsed.path == CALLBACK_PATH and not parsed.fragment,
            "OAuth callback destination differs")
    query = closed_query(parsed.query)
    require(set(query) == {"code", "state"} and query["state"] == state and CODE.fullmatch(query["code"]),
            "OAuth callback code/state bindings differ")
    return parsed.path + "?" + parsed.query, query["code"]


def validate_observations(document, stage):
    require(stage in STAGES and isinstance(document, dict)
            and document.get("schema") == "serverware.privateGoogleObservations/v1",
            "isolated provider observations unavailable")
    consent, refresh, resources = STAGES[stage]
    counts = document.get("counts", {})
    expected = {"authorization_requests": consent, "authorization_codes_issued": consent,
        "authorization_code_exchanges": consent, "token_requests": consent + refresh,
        "token_responses": consent + refresh, "refresh_exchanges": refresh,
        "identity_requests": consent, "resource_requests": resources,
        "resource_gmail.messages.list": resources, "resource_attempts": resources}
    require(set(counts) == {"google", "x"} and counts["x"] == {} and isinstance(counts["google"], dict)
            and all(type(value) is int and value >= 0 for value in counts["google"].values())
            and {key: value for key, value in counts["google"].items() if value}
                == {key: value for key, value in expected.items() if value},
            "provider exchange, refresh or dispatch count differs")
    require(document.get("tokenLifetimes") == {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300}
            and document.get("active") == {"authorizationCodes": 0, "grants": consent},
            "provider lifetime or consumed grant state differs")
    events = document.get("events")
    required = {"authorization_validated": consent, "authorization_code_issued": consent, "authorization_code_exchanged": consent,
        "tokens_issued": consent + refresh, "identity_returned": consent,
        "refresh_token_rotated": refresh, "resource_authorized": resources, "resource_received": resources}
    require(isinstance(events, list) and len(events) <= 16
            and all(isinstance(row, dict) and row.get("provider") == "google"
                    and type(row.get("sequence")) is int and row["sequence"] == index + 1
                    and type(row.get("timestamp_epoch_ms")) is int
                    for index, row in enumerate(events))
            and Counter(row.get("type") for row in events) == Counter({key: value for key, value in required.items() if value}),
            "provider event sequence or operation inventory differs")
    for row in events:
        kind = row["type"]
        if kind in {"authorization_validated", "authorization_code_issued"}:
            require(row.get("requested_scopes") == SCOPES, "provider consent scope evidence differs")
        if kind == "authorization_validated":
            require(row.get("outcome") == "success", "provider consent did not approve the exact request")
        if kind in {"authorization_code_exchanged", "tokens_issued", "refresh_token_rotated"}:
            require(row.get("granted_scopes") == SCOPES, "provider grant scope evidence differs")
        if kind == "authorization_code_exchanged":
            require(row.get("pkce") == "S256", "provider code exchange did not verify PKCE")
        if kind == "identity_returned":
            require(row.get("malformed") is False, "provider identity verification fixture differs")
    require([row.get("grant_type") for row in events if row["type"] == "tokens_issued"]
            == (["authorization_code"] if consent else []) + (["refresh_token"] if refresh else []),
            "provider token issuance origins differ")
    expiry = document.get("initialAccessExpiresAtEpochMs")
    if not consent:
        require(expiry is None and document.get("initialAccessExpired") is False, "fresh provider already issued tokens")
    else:
        require(type(expiry) is int and expiry > 0
                and type(document.get("initialAccessExpired")) is bool, "provider actual expiry unavailable")
        reached = [row for row in events if row["type"] == "resource_authorized"]
        require([row.get("token_generation") for row in reached] == list(range(1, resources + 1))
                and all(row.get("operation") == "gmail.messages.list" for row in reached),
                "resource requests did not use distinct expected token generations")
        if reached:
            require(reached[0]["timestamp_epoch_ms"] < expiry - 60000,
                    "first dispatch was not before the unchanged refresh skew")
        if stage in {"expired", "refreshed"}:
            require(document["initialAccessExpired"] is True, "initial provider token did not actually expire")
        else:
            require(document["initialAccessExpired"] is False, "initial provider token expired prematurely")
        if resources == 2:
            require(reached[1]["timestamp_epoch_ms"] >= expiry + 1000, "second dispatch preceded the expiry checkpoint")
    return {"stage": stage, "counts": dict(sorted(counts["google"].items())),
            "initialAccessExpiresAtEpochMs": expiry, "initialAccessExpired": document["initialAccessExpired"],
            "resourceGenerations": [row["token_generation"] for row in events if row["type"] == "resource_authorized"]}


def no_dispatch_effects(events):
    require(not any(row.get("event_type") in {"data_plane.credential_lease.issued",
        "data_plane.credential.release_started", "credential.oauth_refreshed"} for row in events),
        "negative control acquired credential material or triggered refresh")


def generation_evidence(events, scope, credential_id, wire_commitments):
    connected = [row for row in events if row.get("event_type") == "credential.oauth_connected"]
    refreshed = [row for row in events if row.get("event_type") == "credential.oauth_refreshed"]
    starts = [row for row in events if row.get("event_type") == "data_plane.credential.release_started"]
    require(len(connected) == 1 and len(refreshed) == 1 and len(starts) == 2,
            "OAuth or Rust generation event count differs")
    require(connected[0]["event"].get("credential_id") == credential_id
            and type(connected[0]["event"].get("credential_version")) is int
            and connected[0]["event"]["credential_version"] == 1,
            "initial encrypted credential generation differs")
    refresh = refreshed[0]["event"]
    require(refresh.get("credential_id") == credential_id and refresh.get("provider") == "google"
            and type(refresh.get("previous_credential_version")) is int and refresh["previous_credential_version"] == 1
            and type(refresh.get("credential_version")) is int and refresh["credential_version"] == 2
            and refresh.get("refresh_token_rotated") is True and refresh.get("scopes") == SCOPES,
            "actual persisted automatic refresh generation differs")
    require(all(type(row["event"].get("credential_version")) is int for row in starts)
            and sorted(row["event"]["credential_version"] for row in starts) == [1, 2]
            and all(row["event"].get("credential_ref") == credential_id
                and tuple(row["event"].get(key) for key in ("principal_id", "route_id", "policy_hash")) == scope
                and row["event"].get("method") == "GET" for row in starts),
            "Rust dispatch did not use the two committed credential generations")
    terminals = [row for row in events if row.get("event_type") == "data_plane.response.released"]
    require(len(wire_commitments) == len(terminals) == 2
            and all((row["event"].get("request_digest"), row["event"].get("operation_digest")) in wire_commitments
                    and row["event"].get("response_body_sha256") == "sha256:" + hashlib.sha256(fixture.GMAIL_RESPONSE_BODY).hexdigest()
                    and row["event"].get("response_body_bytes") == len(fixture.GMAIL_RESPONSE_BODY)
                    for row in terminals), "Gmail wire and durable response commitments differ")
    return {"initialCredentialVersion": 1, "refreshedCredentialVersion": 2,
            "generationAuditEventIds": sorted(row["id"] for row in connected + refreshed + starts)}


class GmailTLS(TunnelTLS):
    """Existing bounded CONNECT TLS implementation with the real Gmail SNI."""
    def __init__(self, raw, context, timeout):
        io.RawIOBase.__init__(self)
        self.raw, self.timeout = raw, timeout
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname="gmail.googleapis.com")
        self._perform(self.tls.do_handshake)


class GoogleRefreshCheck(OperatorCatalogCheck):
    def __init__(self, args):
        # The fixture has no outbound interfaces. This proves why the otherwise
        # public-looking Google address is a local bind, before any endpoint use.
        fixture.assert_isolated_network()
        super().__init__(argparse.Namespace(**vars(args), upstream_address="127.0.0.1"))
        self.accounts = Endpoint("https://accounts.google.com", address="127.0.0.1")
        self.upstream = Endpoint(GMAIL_ORIGIN, address="127.0.0.1")
        self.accounts.address = self.upstream.address = fixture.GOOGLE_IP
        self.provider_observations, self.transient_values, self.wire_commitments = [], [], []
        self.negative_observations = []

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        require(re.search(fixture.TOKEN_PATTERN, content) is None
                and fixture.CLIENT_SECRET.encode() not in content, "synthetic provider secret escaped")

    def catalog(self):
        value = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(isinstance(value, dict) and value.get("schema") == "serverware.operatorCatalog/v1"
                and value.get("mode") == "operator-development" and value.get("productionReady") is False
                and value.get("hardwareVerified") is False and value.get("allowed_upstreams") == [GMAIL_ORIGIN]
                and type(value.get("revision")) is int and value["revision"] >= 1
                and all(isinstance(value.get(key), list) for key in COLLECTIONS), "Google catalog profile differs")
        policy = value.get("policy", {})
        require(isinstance(policy.get("policy_hash"), str) and SHA256.fullmatch(policy["policy_hash"])
                and type(policy.get("sequence")) is int and policy["sequence"] > 0, "Google catalog policy unavailable")
        self.snapshot = value
        return value

    def exchange(self, endpoint, target, *, method="GET", payload=None, cookie=None, authenticated=False):
        require(target.startswith("/") and not target.startswith("//") and len(target) <= 8192
                and "\r" not in target and "\n" not in target, "HTTP target differs")
        headers = {"Connection": "close"}
        if authenticated:
            headers["X-Serverware-Admin-Token"] = self.admin_token
        if cookie is not None:
            require(endpoint is self.control, "browser cookie must stay at the control origin")
            headers["Cookie"] = cookie
        body = None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        if payload is not None:
            headers.update({"Content-Type": "application/json", "Origin": fixture.CONTROL_ORIGIN})
        context = self.control_ca if endpoint is self.control else self.upstream_ca
        connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=self.timeout())
        connection.connect = lambda: setattr(connection, "sock", endpoint.connect(self.timeout(), context))
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_HTTP_BODY + 1)
            require(len(raw) <= MAX_HTTP_BODY and len(str(response.getheaders())) <= 16384, "HTTP response exceeds bounds")
            self.clean(raw)
            self.clean(str(response.getheaders()).encode())
            return response.status, response.getheaders(), raw
        finally:
            connection.close()

    def observe(self, stage):
        status, value = self.json_request(self.upstream, fixture.OBSERVATIONS_PATH, context=self.upstream_ca)
        require(status == 200, "provider observation request failed")
        result = validate_observations(value, stage)
        self.provider_observations.append(result)
        return result

    def connect_account(self, before):
        status, headers, raw = self.exchange(self.control, PREFIX + "/oauth/google/start", method="POST",
            payload={"name": self.run_id + "-google", "permission_preset": "gmail_readonly",
                "expected_revision": before["revision"], "expected_policy_hash": before["policy"]["policy_hash"]},
            authenticated=True)
        require(status == 200, "Google start failed or is uncertain; never retry")
        started = json.loads(raw)
        target = authorization_target(started)
        cookie, nonce = browser_cookie(headers, started["state"])
        intent = started.get("operatorGoogleIntent", {})
        require(intent.get("status") == "awaiting_consent" and isinstance(intent.get("id"), str)
                and intent.get("permission_preset") == "gmail_readonly" and intent.get("scopes") == SCOPES,
                "Google consent intent unavailable")
        after_start = self.catalog()
        require(after_start["revision"] == before["revision"] + 2 and not after_start["credentials"]
                and after_start["policy"]["policy_hash"] == before["policy"]["policy_hash"],
                "Google start unexpectedly granted access or failed reconciliation")
        status, headers, raw = self.exchange(self.accounts, target)
        require(status == 302 and raw == b"", "synthetic consent did not return its exact redirect")
        target, code = callback_target(headers, started["state"])
        self.transient_values.extend((started["state"], nonce, code))
        status, _, raw = self.exchange(self.control, target, cookie=cookie)
        require(status == 200 and b"<h1>OAuth credential connected</h1>" in raw
                and b"No application access has been granted" in raw,
                "actual OAuth callback registration failed or is uncertain; never retry")
        after = self.catalog()
        require(after["revision"] == after_start["revision"] + 2 and len(after["credentials"]) == 1
                and not after["applications"] and not after["access_rules"]
                and after["policy"]["policy_hash"] == before["policy"]["policy_hash"],
                "Google callback registration did not reconcile as store-only")
        credential = after["credentials"][0]
        require(credential.get("auth_type") == "google_oauth" and credential.get("status") == "active"
                and credential.get("provider_account") == "operator@example.test"
                and credential.get("provider_subject") == "google-subject-001"
                and credential.get("oauth_client_id") == fixture.CLIENT_ID and credential.get("scopes") == SCOPES
                and credential.get("active_rule_count") == 0, "registered Google account public binding differs")
        intents = self.control_json(PREFIX + "/oauth/google/intents", authenticated=True).get("intents", [])
        require(len(intents) == 1 and intents[0].get("id") == intent["id"]
                and intents[0].get("status") == "connected" and intents[0].get("credential_id") == credential["id"],
                "one-time consent completion did not persist")
        self.results.append("actual_catalog_consent_callback_and_store_only_account_registration")
        return credential

    def tunnel(self, token, *, expected_status=200):
        raw = self.proxy.connect(self.timeout(), self.proxy_ca)
        try:
            raw.sendall((f"CONNECT {GMAIL_AUTHORITY} HTTP/1.1\r\nHost: {GMAIL_AUTHORITY}\r\n"
                         + "Proxy-Authorization: Bearer " + token + "\r\n\r\n").encode("ascii"))
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                raw.settimeout(self.timeout())
                chunk = raw.recv(1)
                require(chunk and len(head) < 16384, "Google CONNECT response incomplete or oversized")
                head.extend(chunk)
            self.clean(bytes(head))
            require(int(head.split(b" ", 2)[1]) == expected_status, "Google CONNECT authorization status differs")
            if expected_status != 200:
                raw.close()
                return None
            return raw
        except BaseException:
            raw.close()
            raise

    def dispatch(self, *, method="GET"):
        raw = self.tunnel(self.client_token)
        try:
            with GmailTLS(raw, self.ca, self.timeout) as tls:
                tls.sendall((f"{method} {fixture.GMAIL_PATH} HTTP/1.1\r\nHost: gmail.googleapis.com\r\n"
                    f"Connection: close\r\nAccept: application/json\r\nUser-Agent: serverware-test-run/{self.run_id}\r\n\r\n").encode("ascii"))
                response = http.client.HTTPResponse(tls)
                try:
                    response.begin()
                    body = response.read(MAX_HTTP_BODY + 1)
                    require(len(body) <= MAX_HTTP_BODY, "Gmail response body exceeds bound")
                    self.clean(body)
                    self.clean(str(response.getheaders()).encode())
                    document = json.loads(body)
                    self.clean(json.dumps(document).encode())
                    if method == "POST":
                        require(response.status == 403 and document.get("allowed") is False
                                and document.get("action") == "deny", "wrong method was not denied")
                    else:
                        fields = response.getheaders()
                        headers = dict((name.lower(), value) for name, value in fields)
                        require(response.status == 200 and body == fixture.GMAIL_RESPONSE_BODY
                                and len(headers) == len(fields) <= 64 and len(str(fields)) <= 16384
                                and headers.get("x-serverware-policy-hash") == self.policy_hash
                                and headers.get("x-serverware-response-body-sha256") == "sha256:" + hashlib.sha256(body).hexdigest(),
                                "normal Rust Gmail response or byte commitment differs")
                        commitments = tuple(headers.get(name) for name in ("x-serverware-request-digest", "x-serverware-operation-digest"))
                        require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in commitments),
                                "normal Rust Gmail request commitments unavailable")
                        self.wire_commitments.append(commitments)
                    return response.status
                finally:
                    response.close()
        finally:
            raw.close()

    def unchanged(self, pinned):
        current = self.warm_cas_snapshot()
        require(current["revision"] == pinned["revision"] and current["policy"]["sequence"] == pinned["policy"]["sequence"]
                and all(current[key] == pinned[key] for key in COLLECTIONS),
                "catalog resources or authority changed during dispatch/refresh")

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0
                for key in COLLECTIONS), "Google acceptance requires an empty fresh catalog")
        self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("fresh_google_catalog")
        self.observe("fresh")
        credential = self.connect_account(initial)
        self.observe("connected")
        application, self.client_token, _ = self.mutate("/applications",
            {"name": self.run_id + "-allowed", "token_lifetime_seconds": 3600},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        unassigned, wrong_app_token, _ = self.mutate("/applications",
            {"name": self.run_id + "-unassigned", "token_lifetime_seconds": 3600},
            collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        rule, _, _ = self.mutate("/access-rules", {"name": self.run_id + "-gmail", "application_id": application["id"],
            "credential_id": credential["id"], "upstream_url": GMAIL_ORIGIN + fixture.GMAIL_PATH, "methods": ["GET"],
            "request_fields": [], "response_fields": [], "response_mode": "unfiltered_json",
            "credential_input": "insert", "query_keys": [], "allowed_headers": ["accept", "user-agent"]},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        pinned, _ = self.wait_catalog_loaded("google_rule_loaded")
        require(len(pinned["credentials"]) == 1 and len(pinned["applications"]) == 2 and len(pinned["access_rules"]) == 1
                and self.resource(pinned, "applications", unassigned["id"]).get("access_status") == "unassigned",
                "wrong-app control is not a valid persisted unassigned application")
        scope = (application["principal_id"], rule["route_id"], self.policy_hash)
        lease_scope = {"purpose": "dispatchSecret", "principal_id": scope[0], "route_id": scope[1],
            "policy_hash": scope[2], "credential_id": credential["id"], "data_plane_binary_digest": self.args.expected_binary_sha256}
        self.tunnel(wrong_app_token, expected_status=403)
        self.observe("connected")
        features.record_negative_phase(self, "valid_unassigned_application", lease_scope)
        no_dispatch_effects(self.audit())
        self.dispatch(method="POST")
        self.observe("connected")
        features.record_negative_phase(self, "wrong_method", lease_scope)
        no_dispatch_effects(self.audit())
        self.unchanged(pinned)
        self.results.append("valid_unassigned_application_and_wrong_method_denied_without_provider_or_lease_effects")
        self.dispatch()
        self.successes.append(scope)
        first = self.observe("first")
        self.results.append("first_normal_rust_connect_uses_consent_token_before_refresh_skew")
        remaining = (first["initialAccessExpiresAtEpochMs"] + 1000 - time.time_ns() // 1_000_000) / 1000
        require(0 < remaining <= 91 and self.deadline - time.monotonic() > remaining + 10,
                "actual provider expiry cannot fit the bounded acceptance window")
        expiry_wait = time.monotonic() + remaining
        while time.monotonic() < expiry_wait:
            time.sleep(max(0.0, min(1.0, expiry_wait - time.monotonic(), self.timeout())))
        self.observe("expired")
        self.unchanged(pinned)
        self.dispatch()
        self.successes.append(scope)
        self.observe("refreshed")
        self.unchanged(pinned)
        audit_ids, attempts = features.verify_audit(self)
        generations = generation_evidence(self.audit(), scope, credential["id"], self.wire_commitments)
        self.observe("refreshed")
        self.results.append("actual_expiry_automatic_refresh_new_generation_and_second_normal_rust_dispatch")
        result = {"ok": True, "schema": "serverware.operatorGoogleRefreshCheck/v1",
            "syntheticOnly": True, "realGoogleVerified": False, "browserUiVerified": False,
            "productionReady": False, "hardwareVerified": False, "checks": self.results,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "credentialId": credential["id"],
            "applicationIds": [application["id"], unassigned["id"]], "ruleId": rule["id"],
            "providerObservations": self.provider_observations, "durableAuditEventIds": audit_ids,
            "auditedRequestAttemptIds": attempts, **generations}
        self.clean(json.dumps(result, sort_keys=True).encode())
        require(all(value not in json.dumps(result, sort_keys=True) for value in self.transient_values),
                "OAuth browser flow material escaped into evidence")
        return result


def run_checks(args):
    check = None
    try:
        require(args.control_base == fixture.CONTROL_ORIGIN and args.operator_origin == fixture.CONTROL_ORIGIN
                and args.management_base == "http://127.0.0.1:9091" and args.proxy_url == "http://127.0.0.1:9090",
                "Google acceptance fixed endpoints differ")
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256)
                and type(args.timeout_seconds) is int and 120 <= args.timeout_seconds <= 180,
                "Google acceptance digest or bounded deadline differs")
        fixture.assert_isolated_network()
        read_google_marker(args.google_fixture_marker_file)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = GoogleRefreshCheck(args)
        return check.run()
    except Exception as error:
        return {"ok": False, "schema": "serverware.operatorGoogleRefreshCheck/v1", "syntheticOnly": True,
            "productionReady": False, "checks": list(check.results) if check else [],
            "providerObservations": check.provider_observations if check else [],
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "google-fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("control-ca-file", "management-ca-file", "proxy-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise CheckFailure("Google acceptance exceeded its process deadline")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 180))
    try:
        result = run_checks(args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
