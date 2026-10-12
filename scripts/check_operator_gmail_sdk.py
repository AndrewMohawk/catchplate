#!/usr/bin/env python3
"""One-shot compiled official Go Gmail SDK acceptance in a network-none fixture.

No build, service launch, provider-token access, timer reset or accepted-run
retry. Original SDK query bytes, provider arrivals and durable gate commitments
are independent oracles. This is not real Google, browser or deployment proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qsl

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_google_refresh as base
from scripts import operator_gmail_sdk_fixture as fixture
from scripts import operator_gmail_sdk_profiles as profiles
from scripts.operator_gmail_sdk_fixture_network import BROWSER_PROXY_ADDRESS, BROWSER_PROXY_URL
from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import CheckFailure, SHA256, require, token_file
from scripts.check_operator_github_examples import _child_exit_status, _cleanup_example_group
from scripts.check_operator_ordinary_client import OrdinaryClientCheck
from scripts.run_operator_x_examples_fixture import failure_site

SCHEMA = "serverware.privateGmailSdkCheck/v1"
PROXY = "https://proxy.operator-basic.example.test:8443"
COMMAND = ("/example-go/google-gmail",)
SOURCE_FILES = ("examples/google-gmail-go/main.go", "examples/google-gmail-go/go.mod", "examples/google-gmail-go/go.sum")
PHASES = ("first", "refreshed", "wrong_outer_ca", "wrong_inner_ca", "wrong_app", "revoked")
STAGES = {"fresh": (0, 0, 0), "connected": (1, 0, 0), "first": (1, 0, 4),
          "expired": (1, 0, 4), "refreshed": (1, 1, 8)}
CASES = ("list_page_1", "message_metadata_1", "list_page_2", "message_metadata_2")
SUMMARY = {"pages": 2, "messages_read": 2, "more_pages": False}
SUCCESS = b'{"pages":2,"messages_read":2,"more_pages":false}\n'
DENIAL = b"Gmail list failed; inspect Serverware audit records and the saved permission (no automatic retry)\n"
DUMMY = "Bearer serverware-gmail-placeholder-v1"
START = "data_plane.credential.release_started"
RELEASE = "data_plane.response.released"
CONNECT = "data_plane.connect.established"
DENIED = "data_plane.connect.denied"
LEASE = "data_plane.credential_lease.issued"
LEASE_REJECT = "data_plane.credential_lease.rejected"
RELOAD = "data_plane.policy.reloaded"
RELOAD_FAILED = "data_plane.policy.reload_failed"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROW_KEYS = {"ordinal", "case", "method", "path", "rawQuery", "hostMatches", "headersMatch", "framingMatch",
    "requestHeaders", "requestBodySha256", "requestBodyBytes", "requestCommitment", "authorized", "status",
    "tokenGeneration", "tokenState", "timestampEpochMs", "responseBodySha256", "responseBodyBytes"}
REQUEST_KEYS = {"case", "generation", "requestDigest", "operationDigest", "responseBodySha256", "responseBodyBytes"}
NEGATIVE_KINDS = {"wrong_outer_ca": None, "wrong_inner_ca": CONNECT, "wrong_app": DENIED, "revoked": DENIED}
TRUST_FILES = {"inner": Path("/client-trust/inner-ca.pem"), "outer": Path("/client-trust/outer-ca.pem"),
    "combined": Path("/client-trust/combined-ca.pem")}


def selected_cases(sdk_pair=False):
    require(type(sdk_pair) is bool, "Gmail SDK selection differs")
    return profiles.PAIR_CASES if sdk_pair else CASES


def selected_stages(sdk_pair=False):
    selected_cases(sdk_pair)
    return {name: (consent, refresh, count * (2 if sdk_pair else 1))
        for name, (consent, refresh, count) in STAGES.items()}


def selected_phases(sdk_pair=False):
    selected_cases(sdk_pair)
    return profiles.PHASES if sdk_pair else PHASES


def base_phase(phase, sdk_pair=False):
    require(phase in selected_phases(sdk_pair), "Gmail SDK phase differs")
    return profiles.split_phase(phase)[1] if sdk_pair else phase


def fixture_proxy(browser_permission):
    require(type(browser_permission) is bool, "Gmail SDK browser mode differs")
    return (BROWSER_PROXY_URL, BROWSER_PROXY_ADDRESS) if browser_permission else (PROXY, "127.0.0.1")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else encoded(value)).hexdigest()


def validate_row(row, ordinal, generation, *, sdk_pair=False):
    cases = selected_cases(sdk_pair)
    require(type(ordinal) is int and 1 <= ordinal <= 2 * len(cases) and type(generation) is int and generation == 1 + (ordinal - 1) // len(cases),
        "Gmail SDK row position differs")
    case = cases[(ordinal - 1) % len(cases)]
    spec = fixture.selected_targets(sdk_pair)[case]
    provider_headers = {"accept": "*/*", "host": "gmail.googleapis.com", "user-agent": "google-api-go-client/0.5",
        "x-goog-api-client": "gl-go/1.23.12 gdcl/0.230.0"}
    if sdk_pair:
        provider_headers = profiles.provider_headers(case)
    public = {"schema": "serverware.privateGmailSdkRequest/v1", "method": "GET", "authority": "gmail.googleapis.com",
        "path": spec["path"], "rawQuery": spec["raw_query"], "headers": provider_headers,
        "bodySha256": digest(b""), "bodyBytes": 0}
    require(type(row) is dict and set(row) == ROW_KEYS and row["case"] == case and row["method"] == "GET"
        and row["path"] == spec["path"] and row["rawQuery"] == spec["raw_query"]
        and all(row[key] is True for key in ("hostMatches", "headersMatch", "framingMatch", "authorized"))
        and row["requestHeaders"] == provider_headers and row["requestBodySha256"] == digest(b"")
        and type(row["requestBodyBytes"]) is int and row["requestBodyBytes"] == 0
        and row["requestCommitment"] == digest(public) and row["tokenState"] == "active"
        and type(row["ordinal"]) is int and row["ordinal"] == ordinal
        and type(row["tokenGeneration"]) is int and row["tokenGeneration"] == generation
        and type(row["status"]) is int and row["status"] == 200
        and type(row["timestampEpochMs"]) is int and row["timestampEpochMs"] > 0
        and row["responseBodySha256"] == digest(spec["body"])
        and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(spec["body"]),
        "Gmail SDK provider target, headers, generation or response differs")
    return True


def observations(document, stage, *, sdk_pair=False):
    stages, cases = selected_stages(sdk_pair), selected_cases(sdk_pair)
    # Per-client checkpoints still bind every preceding accepted arrival.
    partial = stage in {"node_first", "node_refreshed"} and sdk_pair
    require((stage in stages or partial) and type(document) is dict and set(document) == {"schema", "counts", "events", "active", "bounds",
        "tokenLifetimes", "initialAccessExpiresAtEpochMs", "initialAccessExpired", "gmailSdk"}
        and document["schema"] == "serverware.privateGoogleObservations/v1", "Gmail SDK observations unavailable")
    consent, refresh, resources = (1, int(stage == "node_refreshed"), 12 if stage == "node_refreshed" else 4) if partial else stages[stage]
    counts = document["counts"]
    require(type(counts) is dict and set(counts) == {"google", "x"} and counts["x"] == {} and type(counts["google"]) is dict,
        "Gmail SDK provider count shape differs")
    if stage == "expired":
        refresh = counts["google"].get("refresh_exchanges", 0)
        require(type(refresh) is int and refresh in (0, 1), "Gmail SDK expiry refresh count differs")
    expected = {"authorization_requests": consent, "authorization_codes_issued": consent, "authorization_code_exchanges": consent,
        "token_requests": consent + refresh, "token_responses": consent + refresh, "refresh_exchanges": refresh,
        "identity_requests": consent, "resource_requests": resources, "resource_attempts": resources,
        "resource_gmail.messages.list": resources // 2, "resource_gmail.message.get": resources // 2}
    require(all(type(v) is int and 0 <= v <= 32 for v in counts["google"].values())
        and {k: v for k, v in counts["google"].items() if v} == {k: v for k, v in expected.items() if v},
        "Gmail SDK extra provider arrival, retry or exchange")
    require(document["tokenLifetimes"] == {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300}
        and all(type(v) is int for v in document["tokenLifetimes"].values())
        and document["active"] == {"authorizationCodes": 0, "grants": consent}
        and all(type(v) is int for v in document["active"].values()), "Gmail SDK original lifetimes or grant state differs")
    events = document["events"]
    inventory = {"authorization_validated": consent, "authorization_code_issued": consent, "authorization_code_exchanged": consent,
        "identity_returned": consent, "tokens_issued": consent + refresh, "refresh_token_rotated": refresh,
        "resource_received": resources, "resource_authorized": resources}
    require(type(events) is list and len(events) <= (40 if sdk_pair else 24) and all(type(row) is dict and row.get("provider") == "google"
        and type(row.get("sequence")) is int and row["sequence"] == i + 1
        and type(row.get("timestamp_epoch_ms")) is int and row["timestamp_epoch_ms"] > 0 for i, row in enumerate(events))
        and Counter(row.get("type") for row in events) == Counter({k: v for k, v in inventory.items() if v}),
        "Gmail SDK provider event inventory differs")
    for row in events:
        kind = row["type"]
        if kind in {"authorization_validated", "authorization_code_issued"}:
            require(row.get("requested_scopes") == base.SCOPES, "Gmail SDK consent scope differs")
        if kind in {"authorization_code_exchanged", "tokens_issued", "refresh_token_rotated"}:
            require(row.get("granted_scopes") == base.SCOPES, "Gmail SDK grant scope differs")
        if kind == "authorization_validated":
            require(row.get("outcome") == "success", "Gmail SDK consent failed")
        if kind == "authorization_code_exchanged":
            require(row.get("pkce") == "S256", "Gmail SDK PKCE evidence differs")
        if kind == "identity_returned":
            require(row.get("malformed") is False, "Gmail SDK identity evidence differs")
    require([r.get("grant_type") for r in events if r["type"] == "tokens_issued"]
        == (["authorization_code"] if consent else []) + (["refresh_token"] if refresh else []), "Gmail SDK issuance order differs")
    sdk = document["gmailSdk"]
    require(type(sdk) is dict and set(sdk) == {"schema", "maxAttempts", "attempts"}
        and sdk["schema"] == (profiles.OBSERVATION_SCHEMA if sdk_pair else "serverware.privateGmailSdkObservations/v1") and type(sdk["maxAttempts"]) is int
        and sdk["maxAttempts"] == 32 and type(sdk["attempts"]) is list and len(sdk["attempts"]) == resources,
        "Gmail SDK finite receiver differs")
    expiry = document["initialAccessExpiresAtEpochMs"]
    require((type(expiry) is int and expiry > 0) if consent else expiry is None, "Gmail SDK original expiry unavailable")
    require(document["initialAccessExpired"] is (stage in {"expired", "refreshed", "node_refreshed"}), "Gmail SDK actual expiry not reached")
    authorized = [r for r in events if r["type"] == "resource_authorized"]
    received = [r for r in events if r["type"] == "resource_received"]
    for i, row in enumerate(sdk["attempts"]):
        generation = 1 + i // len(cases)
        validate_row(row, i + 1, generation, sdk_pair=sdk_pair)
        event = authorized[i]
        require(type(event.get("token_generation")) is int and event["token_generation"] == generation
            and event.get("operation") == ("gmail.messages.list" if i % 4 in (0, 2) else "gmail.message.get")
            and type(received[i].get("attempt")) is int and received[i]["attempt"] == i + 1,
            "Gmail SDK event generation or operation differs")
        times = (event["timestamp_epoch_ms"], row["timestampEpochMs"], received[i]["timestamp_epoch_ms"])
        require(all(t < expiry - 60000 for t in times) if generation == 1 else all(t >= expiry + 1000 for t in times),
            "Gmail SDK requests did not straddle the original expiry")
    return {"stage": stage, "counts": {k: v for k, v in sorted(expected.items()) if v},
        "initialAccessExpiresAtEpochMs": expiry, "initialAccessExpired": document["initialAccessExpired"],
        "resourceGenerations": [r["token_generation"] for r in authorized], "cases": [r["case"] for r in sdk["attempts"]],
        "refreshCompletedAtExpiry": bool(refresh) if stage == "expired" else None}


def request_commitments(row, *, scope, credential_id, generation, sdk_pair=False):
    validate_row(row, row.get("ordinal"), generation, sdk_pair=sdk_pair)
    require(len(scope) == 3 and SHA256.fullmatch(scope[2]) and UUID.fullmatch(credential_id), "Gmail SDK canonical scope differs")
    operation = {"operation": "gmail.messages.list", "gmailUser": "me"}
    if row["case"].rsplit(":", 1)[-1].startswith("message_"):
        operation = {"operation": "gmail.message.get", "gmailUser": "me", "messageId": row["path"].rsplit("/", 1)[1]}
    canonical = {"v": 3, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": str(generation), "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "gmail.googleapis.com", "path": row["path"],
            "query": [list(pair) for pair in parse_qsl(row["rawQuery"], keep_blank_values=True, encoding="utf-8", errors="strict")],
            "query_mode": "orderedFormV1", "query_wire": row["rawQuery"],
            # The SDK sends no Accept. The receiver's reqwest-added */* is NOT
            # original ingress and must not enter the signed request digest.
            "headers": {"host": "gmail.googleapis.com", "user-agent": "google-api-go-client/0.5",
                "x-goog-api-client": "gl-go/1.23.12 gdcl/0.230.0"},
            "body_sha256": digest(b""), "discard_headers": ["accept-encoding"]}, "operation": operation}
    if sdk_pair:
        canonical["request"]["headers"] = profiles.provider_headers(row["case"])
    return digest(canonical), digest({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}})


def _audit_ordered(events, pairs):
    def when(item):
        value = item.get("created_at")
        require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:\+00:00|Z)", value),
            "Gmail SDK publication audit timestamp differs")
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise CheckFailure("Gmail SDK publication audit timestamp differs") from None
        require(result.tzinfo == timezone.utc, "Gmail SDK publication audit clock differs")
        return result

    # /api/audit omits SQLite rowid and can be newest-first. The verified
    # predecessor hashes prove durable order independently of presentation.
    by_hash = {item["event_hash"]: item for item in events}
    require(len(by_hash) == len(events), "Gmail SDK publication audit hashes collide")
    def precedes(earlier, later):
        if not when(earlier) < when(later):
            return False
        current = later
        for _ in events:
            previous = current.get("prev_event_hash")
            if previous == earlier["event_hash"]:
                return True
            if type(previous) is not str or previous not in by_hash:
                return False
            current = by_hash[previous]
        return False
    return all(precedes(earlier, later) for earlier, later in pairs)


def grant_publication_reload_failures(events, scope, credential_id, *, grant, sdk_pair=False):
    """One known failed dev-attestation observation before the saved grant loads."""
    failures = [row for row in events if row["event_type"] == RELOAD_FAILED]
    require(len(failures) <= 1, "Gmail SDK repeated grant publication reload failure")
    if not failures:
        return 0
    require(type(grant) is dict and set(grant) == {
        "rule_id", "application_id", "revision", "policy_sequence", "previous_policy_hash"}
        and all(type(grant[k]) is str and UUID.fullmatch(grant[k]) for k in ("rule_id", "application_id"))
        and all(type(grant[k]) is int and grant[k] > 0 for k in ("revision", "policy_sequence"))
        and type(grant["previous_policy_hash"]) is str and SHA256.fullmatch(grant["previous_policy_hash"])
        and grant["previous_policy_hash"] != scope[2], "Gmail SDK reload failure lacks explicit grant")
    row = failures[0]
    require(type(row["id"]) is str and SHA256.fullmatch(row["id"])
        and row["event"] == {"component": "serverware-decision-gate-rs", "active_policy_hash": grant["previous_policy_hash"],
            "error": "policy_reload_failed",
            "error_sha256": digest(b"control-plane attestation missing policy_signing_key_id")},
        "Gmail SDK reload failure is not the exact unavailable dev-policy observation")
    created = [r for r in events if r["event_type"] == "operator_catalog.access_rule.created"]
    reloaded = [r for r in events if r["event_type"] == RELOAD and r["event"].get("policy_hash") == scope[2]]
    require(len(created) == len(reloaded) == 1, "Gmail SDK reload failure lacks one saved grant and reload")
    before, after = created[0], reloaded[0]
    require(type(before["id"]) is str and UUID.fullmatch(before["id"])
        and type(after["id"]) is str and SHA256.fullmatch(after["id"])
        and all(before["event"].get(k) == v for k, v in {"resource_type": "access_rule",
            "resource_id": grant["rule_id"], "application_id": grant["application_id"], "credential_id": credential_id,
            "revision": grant["revision"], "policy_sequence": grant["policy_sequence"], "policy_hash": scope[2]}.items())
        and all(type(before["event"].get(k)) is int for k in ("revision", "policy_sequence"))
        and after["event"].get("previous_policy_hash") == grant["previous_policy_hash"]
        and type(after["event"].get("policy_sequence")) is int
        and after["event"]["policy_sequence"] == grant["policy_sequence"],
        "Gmail SDK reload failure is outside the exact saved grant transition")
    releases = [r for r in events if r["event_type"] in {START, RELEASE}]
    count = 2 * len(selected_cases(sdk_pair))
    require(Counter(r["event_type"] for r in releases) == Counter({START: count, RELEASE: count})
        and _audit_ordered(events, [(before, row), (row, after), *((after, r) for r in releases)]),
        "Gmail SDK reload failure is not before reads and between grant and reload")
    return 1


def revocation_publication_rejections(events, rejections, scope, credential_id, *, expected_binary_sha256, revocation):
    """One observed fail-closed metadata race, not a general renewal allowance."""
    require(len(rejections) <= 1, "Gmail SDK repeated revocation publication rejection")
    if not rejections:
        return 0
    require(type(revocation) is dict and set(revocation) == {
        "rule_id", "application_id", "revision", "policy_sequence", "policy_hash"}
        and all(type(revocation[k]) is str and UUID.fullmatch(revocation[k]) for k in ("rule_id", "application_id"))
        and all(type(revocation[k]) is int and revocation[k] > 0 for k in ("revision", "policy_sequence"))
        and type(revocation["policy_hash"]) is str and SHA256.fullmatch(revocation["policy_hash"])
        and revocation["policy_hash"] != scope[2], "Gmail SDK publication rejection lacks explicit revocation")
    row = rejections[0]
    event = row["event"]
    fixed = {"outcome": "rejected", "purpose": "generationMetadata",
        "principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
        "credential_id": credential_id, "data_plane_binary_digest": expected_binary_sha256,
        "credential_count": 0, "credential_ids": [], "release_quota_claim_count": 0, "requested_max_ttl_seconds": 5}
    null_fields = {"expected_credential_version", "expected_metadata_sha256", "release_attempt_id",
        "release_binding_digest", "release_kind", "release_reservation_id", "release_request_digest",
        "release_operation_digest", "issued_at_epoch_ms", "expires_at_epoch_ms"}
    require(type(event) is dict and set(event) == set(fixed) | null_fields | {
        "status_code", "reason", "recipient_key_id", "recipient_nonce_sha256", "recipient_attestation_present"}
        and all(event.get(k) == v for k, v in fixed.items())
        # The two consecutive producer guards reject before route authority,
        # nonce reservation or credential access. No other 409/503 is admitted.
        and (event.get("status_code"), event.get("reason")) in (
            (503, "active signed policy bundle is unavailable"), (409, "data-plane policy hash is not active"))
        and all(type(event.get(k)) is int for k in ("status_code", "credential_count",
            "release_quota_claim_count", "requested_max_ttl_seconds"))
        and type(event["credential_ids"]) is list and event["recipient_attestation_present"] is False
        and all(event[k] is None for k in null_fields)
        and all(type(event[k]) is str and SHA256.fullmatch(event[k]) for k in ("recipient_key_id", "recipient_nonce_sha256")),
        "Gmail SDK publication rejection differs from empty old-policy metadata refusal")
    revoked = [r for r in events if r["event_type"] == "operator_catalog.access_rule.revoked"]
    reloaded = [r for r in events if r["event_type"] == RELOAD and r["event"].get("policy_hash") == revocation["policy_hash"]]
    require(len(revoked) == len(reloaded) == 1, "Gmail SDK publication rejection has no unique revocation boundary")
    before, after = revoked[0], reloaded[0]
    require(type(before["id"]) is str and UUID.fullmatch(before["id"])
        and type(after["id"]) is str and SHA256.fullmatch(after["id"])
        and all(before["event"].get(k) == v for k, v in {"resource_type": "access_rule",
            "resource_id": revocation["rule_id"], "application_id": revocation["application_id"], "credential_id": credential_id,
            "revision": revocation["revision"], "policy_sequence": revocation["policy_sequence"],
            "policy_hash": revocation["policy_hash"]}.items())
        and all(type(before["event"].get(k)) is int for k in ("revision", "policy_sequence"))
        and after["event"].get("previous_policy_hash") == scope[2]
        and type(after["event"].get("policy_sequence")) is int
        and after["event"]["policy_sequence"] == revocation["policy_sequence"],
        "Gmail SDK publication rejection is outside the exact rule and policy transition")

    require(_audit_ordered(events, [(before, row), (row, after),
        *((item, before) for item in events if item["event_type"] in {START, RELEASE})]),
        "Gmail SDK publication rejection is not after reads and between revoke and reload")
    return 1


def generation_evidence(events, scope, credential_id, commitments, *, expected_binary_sha256, revocation=None, sdk_pair=False):
    cases = selected_cases(sdk_pair)
    count = 2 * len(cases)
    features.audit_cutoff(events)  # Includes unique row IDs and valid chain hashes.
    require(type(expected_binary_sha256) is str and SHA256.fullmatch(expected_binary_sha256),
        "Gmail SDK expected gate binary digest differs")
    require(type(commitments) is list and len(commitments) == count and all(type(r) is dict and set(r) == REQUEST_KEYS for r in commitments),
        "Gmail SDK commitment inventory differs")
    for i, row in enumerate(commitments):
        require(row["case"] == cases[i % len(cases)] and type(row["generation"]) is int and row["generation"] == 1 + i // len(cases)
            and all(type(row[k]) is str and SHA256.fullmatch(row[k]) for k in ("requestDigest", "operationDigest", "responseBodySha256"))
            and row["responseBodySha256"] == digest(fixture.selected_targets(sdk_pair)[row["case"]]["body"])
            and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(fixture.selected_targets(sdk_pair)[row["case"]]["body"]),
            "Gmail SDK typed commitment differs")
    require(len({r["requestDigest"] for r in commitments}) == len({r["operationDigest"] for r in commitments}) == count,
        "Gmail SDK canonical commitments reused")
    for row in events:
        event, kind = row.get("event", {}), row.get("event_type")
        if kind.startswith("data_plane.") or kind in {"credential.oauth_connected", "credential.oauth_refreshed"}:
            # Lease outcomes are recorded by the app, not ingested from the
            # gate's hash-identified producer stream (app.py credential lease).
            pattern = SHA256 if kind.startswith("data_plane.") and kind not in {LEASE, LEASE_REJECT} else UUID
            require(pattern.fullmatch(row["id"]), "Gmail SDK audit row namespace differs")
        if kind in {"credential.oauth_connected", "credential.oauth_refreshed", START}:
            require(type(event.get("credential_version")) is int, "Gmail SDK audit generation is not an integer")
        if kind == "credential.oauth_refreshed":
            require(type(event.get("previous_credential_version")) is int and event.get("refresh_token_rotated") is True,
                "Gmail SDK previous generation or rotation differs")
    actual, pairs = features.release_attempt_pairs(events, Counter({scope: count}))
    require(actual == Counter({scope: count}) and len(pairs) == count, "Gmail SDK durable request pair inventory differs")
    connected = [row for row in events if row["event_type"] == "credential.oauth_connected"]
    refreshed = [row for row in events if row["event_type"] == "credential.oauth_refreshed"]
    starts = [row for row in events if row["event_type"] == START]
    terminals = [row for row in events if row["event_type"] == RELEASE]
    require(len(connected) == len(refreshed) == 1 and len(starts) == len(terminals) == count,
        "Gmail SDK durable generation inventory differs")
    require(connected[0]["event"].get("credential_id") == credential_id
        and connected[0]["event"]["credential_version"] == 1, "Gmail SDK initial persisted generation differs")
    require(all(refreshed[0]["event"].get(k) == v for k, v in {"credential_id": credential_id, "provider": "google",
        "previous_credential_version": 1, "credential_version": 2, "refresh_token_rotated": True, "scopes": base.SCOPES}.items()),
        "Gmail SDK automatic refresh did not persist exactly one new generation")
    expected = {(item["requestDigest"], item["operationDigest"]): item for item in commitments}
    observed = set()
    starts_by_attempt = {row["event"].get("attempt_id"): row for row in starts}
    require(len(starts_by_attempt) == count, "Gmail SDK release-start identities collide")
    for row in terminals:
        event = row["event"]
        key = (event.get("request_digest"), event.get("operation_digest"))
        require(key in expected and key not in observed, "Gmail SDK durable release lacks its exact wire commitment")
        observed.add(key)
        item = expected[key]
        start = starts_by_attempt.get(event.get("attempt_id"), {}).get("event", {})
        require(start.get("credential_ref") == credential_id and type(start.get("credential_version")) is int
            and start["credential_version"] == item["generation"]
            and all(tuple(source.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
                and source.get("method") == "GET" for source in (start, event))
            and (start.get("request_digest"), start.get("operation_digest")) == key
            and event.get("response_body_sha256") == item["responseBodySha256"]
            and type(event.get("response_body_bytes")) is int and event["response_body_bytes"] == item["responseBodyBytes"],
            "Gmail SDK same-account/app generation, attempt or response bytes do not join")
    all_rejections = [row for row in events if row["event_type"] == LEASE_REJECT]
    publication = [row for row in all_rejections if row["event"].get("purpose") == "generationMetadata"]
    publication_count = revocation_publication_rejections(events, publication, scope, credential_id,
        expected_binary_sha256=expected_binary_sha256, revocation=revocation)
    rejections = [row for row in all_rejections if row not in publication]
    require(len(rejections) <= 1, "Gmail SDK repeated credential lease rejection")
    for row in rejections:
        event = row["event"]
        fixed = {"outcome": "rejected", "status_code": 409, "reason": "generationAdvancedBeforeEnvelope",
            "purpose": "dispatchSecret", "expected_credential_version": 1,
            "principal_id": scope[0], "route_id": scope[1], "policy_hash": scope[2],
            "credential_id": credential_id, "data_plane_binary_digest": expected_binary_sha256,
            "credential_count": 0, "credential_ids": [], "release_quota_claim_count": 0}
        null_fields = {"release_attempt_id", "release_binding_digest", "release_kind", "release_reservation_id",
            "release_request_digest", "release_operation_digest", "issued_at_epoch_ms", "expires_at_epoch_ms"}
        require(all(event.get(k) == v for k, v in fixed.items())
            and all(type(event.get(k)) is int for k in ("status_code", "expected_credential_version",
                "credential_count", "release_quota_claim_count"))
            and type(event.get("credential_ids")) is list
            and event.get("recipient_attestation_present") is False
            and all(type(event.get(k)) is str and SHA256.fullmatch(event[k])
                for k in ("expected_metadata_sha256", "recipient_nonce_sha256"))
            and all(k in event and event[k] is None for k in null_fields),
            "Gmail SDK lease rejection lacks the exact no-envelope generation rollover")
    # A single signed pre-envelope rollover is not an SDK/provider retry. The
    # same evidence above must still contain one persisted 1->2 refresh and
    # exactly four successful requests for each generation; denial controls
    # below do not permit any new rejected lease.
    return {"initialCredentialVersion": 1, "refreshedCredentialVersion": 2, "canonicalRequestVersion": 3,
        "generationAuditEventIds": sorted(row["id"] for row in connected + refreshed + starts),
        "reconciliationRejections": len(rejections), "revocationPublicationRejections": publication_count}


def validate_client_result(phase, code, out, err, *, sdk_pair=False):
    selected = base_phase(phase, sdk_pair)
    require(type(code) is int and type(out) is bytes and type(err) is bytes,
        "Gmail SDK process result shape differs")
    positive = selected in {"first", "refreshed"}
    denial = profiles.FAILURES[profiles.split_phase(phase)[0]] if sdk_pair else DENIAL
    require((code == 0 and out == SUCCESS and err == b"") if positive else (code == 1 and out == b"" and err == denial),
        "Gmail SDK exact count summary or fixed failure differs")
    return {"phase": phase, "exitCode": code, "summary": dict(SUMMARY) if positive else None}


def validate_no_arrivals(before, after, *, sdk_pair=False):
    observations(before, "refreshed", sdk_pair=sdk_pair); observations(after, "refreshed", sdk_pair=sdk_pair)
    require(before == after, "denied Gmail SDK attempt changed provider observations")
    return True


def client_environment(application, token, phase):
    require(phase in PHASES and type(application) is str and UUID.fullmatch(application)
        and type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "Gmail SDK app identity differs")
    inner, outer = TRUST_FILES["inner"], TRUST_FILES["outer"]
    if phase == "wrong_outer_ca":
        inner, outer = TRUST_FILES["outer"], TRUST_FILES["inner"]
    elif phase == "wrong_inner_ca":
        inner, outer = TRUST_FILES["outer"], TRUST_FILES["combined"]
    # No ambient PATH/HOME/GOOGLE_*/GODEBUG/SSL_CERT_*/proxy or credential vars.
    return {"LANG": "C.UTF-8", "SERVERWARE_PROXY_URL": PROXY, "SERVERWARE_APP_ID": application,
        "SERVERWARE_PROXY_TOKEN": token, "SERVERWARE_CA_FILE": str(inner), "SERVERWARE_PROXY_CA_FILE": str(outer)}


def run_example(environment, seconds, *, command=COMMAND):
    require(command in (COMMAND, *profiles.COMMANDS.values()), "Gmail SDK fixed entrypoint differs")
    require(0 < seconds <= 30 and set(environment) == {"LANG", "SERVERWARE_PROXY_URL", "SERVERWARE_APP_ID",
        "SERVERWARE_PROXY_TOKEN", "SERVERWARE_CA_FILE", "SERVERWARE_PROXY_CA_FILE"}, "Gmail SDK process boundary differs")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, close_fds=True, start_new_session=True)
    output = {"out": bytearray(), "err": bytearray()}
    try:
        with selectors.DefaultSelector() as selected:
            for stream, key in ((process.stdout, "out"), (process.stderr, "err")):
                selected.register(stream, selectors.EVENT_READ, key)
            while selected.get_map():
                require(time.monotonic() < deadline, "Gmail SDK process deadline exceeded")
                for key, _ in selected.select(min(0.1, max(0.001, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 2048)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    else:
                        output[key.data].extend(chunk)
                        require(len(output[key.data]) <= 1024, "Gmail SDK process output bound exceeded")
        while True:
            code = _child_exit_status(process)
            if code is not None:
                return code, bytes(output["out"]), bytes(output["err"])
            require(time.monotonic() < deadline, "Gmail SDK process deadline exceeded")
            time.sleep(min(0.01, max(0.001, deadline - time.monotonic())))
    finally:
        try:
            _cleanup_example_group(process)
        finally:
            process.stdout.close(); process.stderr.close()


def read_pin(path, maximum):
    require(path.is_absolute() and path.resolve() == path, "Gmail SDK file path differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "Gmail SDK file custody differs")
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        final = os.fstat(descriptor)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(info) == identity(final) and len(chunks) == info.st_size, "Gmail SDK file changed while pinned")
        return identity(info), bytes(chunks)
    finally:
        os.close(descriptor)


def require_bundle(catalog):
    """Pure capability check, without importing the older Requests workload."""
    bundles = catalog.get("capabilities", {}).get("operation_bundles")
    require(type(bundles) is list, "Gmail SDK bundle capability unavailable")
    matches = [item for item in bundles if type(item) is dict and item.get("operation_bundle") == "gmail_read_v1"]
    require(len(matches) == 1, "Gmail SDK bundle capability missing or duplicated")
    item = matches[0]
    require(all(item.get(k) == v for k, v in {
        "create_path": "/api/operator-demo/access-rules/gmail-read", "credential_type": "google_oauth",
        "permission_preset": "gmail_readonly", "api_origin": base.GMAIL_ORIGIN, "methods": ["GET"],
        "paths": [base.fixture.GMAIL_PATH, base.fixture.GMAIL_PATH + "/{message_id}"],
        "query_mode": "orderedFormV1", "age_policy": {"mode": "unrestricted"},
        "response_mode": "gmail_read_json_v1"}.items()), "Gmail SDK bundle capability contract differs")
    contract = item.get("response_contract", {})
    require(contract.get("mode") == "gmailReadJsonV1" and contract.get("success_status_codes") == [200]
        and contract.get("content_types") == ["application/json"] and contract.get("body_presence") == "required"
        and contract.get("unlisted_header_policy") == "discardUnselectedV1", "Gmail SDK response capability differs")


def require_rule(rule, application_id, credential_id):
    require(type(rule) is dict and all(rule.get(k) == v for k, v in {
        "operation_bundle": "gmail_read_v1", "query_mode": "orderedFormV1", "age_policy": {"mode": "unrestricted"},
        "response_mode": "gmail_read_json_v1", "credential_input": "replace_exact", "placeholder": DUMMY,
        "methods": ["GET"], "request_fields": [], "response_fields": [],
        "query_keys": ["alt", "format", "includeSpamTrash", "labelIds", "maxResults", "metadataHeaders", "pageToken", "prettyPrint", "q"],
        "allowed_headers": ["accept", "user-agent", "x-goog-api-client"], "application_id": application_id,
        "credential_id": credential_id, "upstream_url": base.GMAIL_ORIGIN + base.fixture.GMAIL_PATH, "status": "active"}.items())
        and "request_body_mode" not in rule, "Gmail SDK exact saved rule differs")


class GmailSdkCheck(base.GoogleRefreshCheck):
    audit_drained = OrdinaryClientCheck.audit_drained
    sdk_pair = False

    def __init__(self, args):
        self.phase = "startup"
        self.sdk_pair = getattr(args, "sdk_pair", False)
        selected_cases(self.sdk_pair)
        require(not (self.sdk_pair and getattr(args, "browser_permission", False)), "paired browser mode refused")
        super().__init__(args)
        expected_url, expected_address = fixture_proxy(getattr(args, "browser_permission", False))
        require(args.proxy_url == expected_url and self.control.address == self.management.address == "127.0.0.1"
            and self.proxy.address == expected_address,
            "Gmail SDK fixed local peer differs")
        self.completed, self.denials, self.cutoffs = [], [], []
        self.pins = {}
        sources = profiles.SOURCES if self.sdk_pair else SOURCE_FILES
        binary = Path("/node" if self.sdk_pair else COMMAND[0])
        for path, maximum in [(binary, 128 * 1024**2 if self.sdk_pair else 64 * 1024**2),
                *[(Path("/app") / name, 512 * 1024) for name in sources],
                *[(path, 131072) for path in TRUST_FILES.values()]]:
            self.pins[path] = (maximum, read_pin(path, maximum))
        require(hashlib.sha256(self.pins[binary][1][1]).hexdigest()
            == (profiles.NODE_SHA256 if self.sdk_pair else args.expected_go_sha256),
            "Gmail SDK compiled binary pin differs")
        trust = {name: self.pins[path][1][1] for name, path in TRUST_FILES.items()}
        require(trust["inner"] != trust["outer"] and trust["combined"] == trust["outer"] + trust["inner"]
            and all(b"PRIVATE KEY" not in raw and b"BEGIN CERTIFICATE" in raw for raw in trust.values()),
            "Gmail SDK distinct per-hop public roots differ")
        self.source_hashes = {name: hashlib.sha256(self.pins[Path("/app") / name][1][1]).hexdigest() for name in sources}
        self.current_dependencies()

    def current_dependencies(self):
        # Hash the complete immutable payload only at entry and exit, not per request.
        if self.sdk_pair:
            from scripts import prepare_operator_gmail_sdk_fixture as recipe
            value = recipe.paired_dependencies(Path("/app") / profiles.NODE_MODULES,
                Path("/example-python"), Path(profiles.PYTHON_PACKAGES))
            require(recipe.dependencies_sha256(value) == self.args.expected_dependencies_sha256,
                "Gmail SDK paired dependencies changed")
            require(hashlib.sha256(read_pin(Path("/usr/lib/x86_64-linux-gnu/libatomic.so.1"), 1024**2)[1]).hexdigest()
                == recipe.LIBATOMIC_SHA256, "Gmail SDK runtime library differs")

    def current_files(self):
        require(all(read_pin(path, maximum) == pinned for path, (maximum, pinned) in self.pins.items()),
            "Gmail SDK compiled binary, sources or trust files changed")

    def observe(self, stage, *, retain=True):
        status, document = self.json_request(self.upstream, base.fixture.OBSERVATIONS_PATH, context=self.upstream_ca)
        require(status == 200, "Gmail SDK provider observations failed")
        safe = observations(document, stage, sdk_pair=self.sdk_pair)
        if self.provider_observations:
            original = self.provider_observations[1]["initialAccessExpiresAtEpochMs"] if len(self.provider_observations) > 1 else None
            require(original is None or safe["initialAccessExpiresAtEpochMs"] == original, "Gmail SDK original expiry changed")
        if retain:
            self.provider_observations.append(safe)
        return document

    def settled_audit(self):
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        events = self.audit(); features.audit_cutoff(events)
        return events

    def client(self, phase, application, token):
        self.phase = phase; self.current_files()
        if getattr(self.args, "browser_permission", False):
            from scripts.operator_gmail_sdk_browser import copied_phase_environment
            environment = copied_phase_environment(getattr(self, "browser_client_environment", None),
                application=application["id"], token=token, phase=phase)
        else:
            environment = client_environment(application["id"], token, base_phase(phase, self.sdk_pair))
        # The joined browser path uses actual copied fields; only the explicit
        # existing denial controls change that environment. No shell is evaluated.
        options = {"command": profiles.COMMANDS[profiles.split_phase(phase)[0]]} if self.sdk_pair else {}
        result = run_example(environment, min(30, self.deadline - time.monotonic()), **options)
        self.current_files(); self.clean(result[1]); self.clean(result[2])
        self.completed.append(validate_client_result(phase, *result, sdk_pair=self.sdk_pair))

    def accept(self, document):
        rows = document["gmailSdk"]["attempts"]
        require(len(rows) == len(self.wire_commitments) + 4, "Gmail SDK batch did not add exactly four requests")
        for row in rows[len(self.wire_commitments):]:
            generation = row["tokenGeneration"]
            request, operation = request_commitments(row, scope=self.scope, credential_id=self.credential_id,
                generation=generation, sdk_pair=self.sdk_pair)
            self.wire_commitments.append({"case": row["case"], "generation": generation, "requestDigest": request,
                "operationDigest": operation, "responseBodySha256": row["responseBodySha256"], "responseBodyBytes": row["responseBodyBytes"]})
            self.successes.append(self.scope)

    def accept_batch(self, phase, application, token):
        for client in (profiles.CLIENTS if self.sdk_pair else (None,)):
            self.client(client + ":" + phase if client else phase, application, token)
            partial = client == "node"
            document = self.observe("node_" + phase if partial else phase, retain=not partial)
            self.accept(document)
        return document

    def deny(self, phase, application, token, baseline_provider):
        before = features.audit_cutoff(self.settled_audit())
        self.client(phase, application, token)
        validate_no_arrivals(baseline_provider, self.observe("refreshed", retain=False), sdk_pair=self.sdk_pair)
        kind = NEGATIVE_KINDS[base_phase(phase, self.sdk_pair)]
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in before.items()), "Gmail SDK denial audit prefix changed")
            rows = [r for r in events if r["id"] not in before]
            counts = Counter(r["event_type"] for r in rows)
            require(set(counts) <= {LEASE, kind} and counts[kind] <= int(kind is not None),
                "Gmail SDK denial dispatched, retried or changed authority")
            for row in rows:
                event = row["event"]
                if row["event_type"] == LEASE:
                    require(tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == self.scope
                        and event.get("credential_id") == self.credential_id and event.get("purpose") in {"generationMetadata", "dispatchSecret"}
                        and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256,
                        "Gmail SDK denial caused an unrelated credential lease")
                else:
                    require(event.get("method") == "CONNECT" and event.get("target") == "gmail.googleapis.com:443"
                        and event.get("outcome") == ("established" if kind == CONNECT else "denied")
                        and event.get("principal_id") == (self.scope[0] if kind == CONNECT else None),
                        "Gmail SDK TLS or application denial audit differs")
            if counts[kind] == int(kind is not None) and self.audit_drained():
                self.cutoffs.append(cutoff)
                count = 2 * len(selected_cases(self.sdk_pair))
                self.denials.append({"phase": phase, "providerAttemptsBefore": count, "providerAttemptsAfter": count,
                    "auditEventType": kind, "auditEventId": next((r["id"] for r in rows if r["event_type"] == kind), None)})
                return
            time.sleep(min(0.1, self.timeout()))

    def deny_batch(self, phase, application, token, provider):
        for client in (profiles.CLIENTS if self.sdk_pair else (None,)):
            self.deny(client + ":" + phase if client else phase, application, token, provider)

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[k] and initial["limits"][k]["retained"] == 0 for k in COLLECTIONS),
            "Gmail SDK acceptance requires a fresh empty catalog")
        require_bundle(initial)
        require(initial.get("capabilities", {}).get("application_proxy_authentication") == {
            "schema": "serverware.operatorProxyAuthentication/v1", "modes": ["bearer", "basic_and_bearer_v1"],
            "path": "/api/operator-demo/applications/proxy-authentication"}, "Gmail SDK Basic proxy capability unavailable")
        self.policy_hash = initial["policy"]["policy_hash"]; self.wait_catalog_loaded("gmail_sdk_fresh")
        baseline = features.audit_cutoff(self.settled_audit()); self.observe("fresh")
        credential = self.connect_account(initial); self.credential_id = credential["id"]; self.observe("connected")
        apps = []
        for label in ("inbox", "unassigned"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + label, "token_lifetime_seconds": 3600,
                "proxy_authentication": "basic_and_bearer_v1"}, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            require(app.get("proxy_authentication") == "basic_and_bearer_v1", "Gmail SDK saved app proxy auth differs")
            apps.append((app, token))
        (app, self.client_token), (unassigned, wrong_token) = apps
        if getattr(self.args, "browser_permission", False):
            from scripts.operator_gmail_sdk_browser import create_permission
            self.phase = "browser_permission"
            rule, _ = create_permission(self, app, credential)
            # This is a fresh independent persisted-audit read, before any SDK
            # provider request, not an assertion supplied by the browser.
            features.verify_audit(self)
        else:
            rule, _, _ = self.mutate("/access-rules/gmail-read", {"name": self.run_id + "-sdk", "application_id": app["id"],
                "credential_id": credential["id"], "operation_bundle": "gmail_read_v1", "age_policy": {"mode": "unrestricted"},
                "credential_input": "replace_exact", "placeholder": DUMMY}, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
        require_rule(rule, app["id"], credential["id"])
        pinned, _ = self.wait_catalog_loaded("gmail_sdk_rule")
        require_rule(self.resource(pinned, "access_rules", rule["id"]), app["id"], credential["id"])
        require([len(pinned[k]) for k in COLLECTIONS] == [1, 2, 1]
            and self.resource(pinned, "applications", unassigned["id"]).get("access_status") == "unassigned",
            "Gmail SDK exact account/app/grant inventory differs")
        self.scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        first = self.accept_batch("first", app, self.client_token); self.unchanged(pinned)
        expiry = first["initialAccessExpiresAtEpochMs"]
        remaining = (expiry + 1000 - time.time_ns() // 1_000_000) / 1000
        require(0 < remaining <= 91 and self.deadline - time.monotonic() > remaining + 25,
            "Gmail SDK original expiry does not fit the one-shot deadline")
        until = time.monotonic() + remaining
        while time.monotonic() < until:
            time.sleep(max(0, min(1, until - time.monotonic(), self.timeout())))
        self.observe("expired"); self.unchanged(pinned)
        provider = self.accept_batch("refreshed", app, self.client_token)
        self.unchanged(pinned)
        features.verify_audit(self)
        generation_evidence(self.settled_audit(), self.scope, credential["id"], self.wire_commitments,
            expected_binary_sha256=self.args.expected_binary_sha256, sdk_pair=self.sdk_pair)
        self.deny_batch("wrong_outer_ca", app, self.client_token, provider)
        self.deny_batch("wrong_inner_ca", app, self.client_token, provider)
        self.deny_batch("wrong_app", unassigned, wrong_token, provider); self.unchanged(pinned)
        self.phase = "revoke"
        self.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.revoked", authority_changed=True)
        revoked, _ = self.wait_catalog_loaded("gmail_sdk_revoked")
        require(revoked["revision"] == pinned["revision"] + 1
            and revoked["policy"]["sequence"] == pinned["policy"]["sequence"] + 1
            and self.resource(revoked, "access_rules", rule["id"])["status"] == "revoked"
            and self.resource(revoked, "credentials", credential["id"])["status"] == "active"
            and self.resource(revoked, "applications", app["id"])["token_status"] == "valid",
            "Gmail SDK controlled revocation or retained account/app differs")
        self.deny_batch("revoked", app, self.client_token, provider); self.unchanged(revoked)
        audit_ids, attempts = features.verify_audit(self); events = self.settled_audit()
        generations = generation_evidence(events, self.scope, credential["id"], self.wire_commitments,
            expected_binary_sha256=self.args.expected_binary_sha256, sdk_pair=self.sdk_pair,
            revocation={"rule_id": rule["id"], "application_id": app["id"], "revision": revoked["revision"],
                "policy_sequence": revoked["policy"]["sequence"], "policy_hash": revoked["policy"]["policy_hash"]})
        grant_failures = grant_publication_reload_failures(events, self.scope, credential["id"], sdk_pair=self.sdk_pair,
            grant={"rule_id": rule["id"], "application_id": app["id"], "revision": pinned["revision"],
                "policy_sequence": pinned["policy"]["sequence"], "previous_policy_hash": initial["policy"]["policy_hash"]})
        cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for prior in [baseline, *self.cutoffs] for k, v in prior.items()),
            "Gmail SDK audit history changed")
        named = Counter(r["event_type"] for r in events if r["id"] not in baseline and
            (r["event_type"].startswith("data_plane.") or r["event_type"] in {"credential.oauth_connected", "credential.oauth_refreshed"}))
        validate_no_arrivals(provider, self.observe("refreshed", retain=False), sdk_pair=self.sdk_pair)
        self.current_files(); self.current_dependencies()
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realGoogleVerified": False,
            "browserUiVerified": False, "productionReady": False, "hardwareVerified": False, "publicDnsVerified": False,
            "actualExampleEntrypoint": True, "auditChainVerified": True, "separateOuterInnerTrust": True,
            "catalogUnchangedAcrossRefresh": True, "providerAttempts": 2 * len(selected_cases(self.sdk_pair)), "automaticRefreshes": 1,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "exampleSourceSha256": self.source_hashes, "credentialId": credential["id"],
            "applicationIds": [app["id"], unassigned["id"]], "ruleId": rule["id"], "policyHash": self.scope[2],
            "revokedPolicyHash": self.policy_hash, "policyRevisions": {"accepted": pinned["revision"], "revoked": revoked["revision"]},
            "originalAccessExpiresAtEpochMs": expiry, "refreshCompletedAtExpiry": self.provider_observations[3]["refreshCompletedAtExpiry"],
            "completed": self.completed, "providerObservations": self.provider_observations, "requests": self.wire_commitments,
            "negativeControls": self.denials, "durableAuditEventIds": audit_ids, "auditAttemptIds": attempts,
            "namedAuditInventory": dict(sorted(named.items())), "grantPublicationReloadFailures": grant_failures, **generations}
        if self.sdk_pair:
            result.pop("goExampleSha256")
            result.update(schema=profiles.CHECK_SCHEMA, nodeExampleSha256=profiles.NODE_SHA256,
                sdkDependenciesSha256=self.args.expected_dependencies_sha256)
        validate_success_result(result); serialized = encoded(result); self.clean(serialized)
        require(all(value.encode() not in serialized for value in self.transient_values), "Gmail SDK OAuth flow material escaped")
        return result


def validate_success_result(value):
    """Closed pure runner predicate; actual one-shot exit zero is also required."""
    require(type(value) is dict and value.get("schema") in (SCHEMA, profiles.CHECK_SCHEMA), "Gmail SDK result schema differs")
    paired = value["schema"] == profiles.CHECK_SCHEMA
    cases, phases, stages = selected_cases(paired), selected_phases(paired), selected_stages(paired)
    count, clients = 2 * len(cases), 2 if paired else 1
    true_flags = {"ok", "syntheticOnly", "actualExampleEntrypoint", "auditChainVerified", "separateOuterInnerTrust", "catalogUnchangedAcrossRefresh"}
    false_flags = {"realGoogleVerified", "browserUiVerified", "productionReady", "hardwareVerified", "publicDnsVerified"}
    fields = true_flags | false_flags | {"schema", "providerAttempts", "automaticRefreshes", "dataPlaneBinaryDigest", "goExampleSha256",
        "exampleSourceSha256", "credentialId", "applicationIds", "ruleId", "policyHash", "revokedPolicyHash", "policyRevisions",
        "originalAccessExpiresAtEpochMs", "refreshCompletedAtExpiry", "completed", "providerObservations", "requests", "negativeControls",
        "durableAuditEventIds", "auditAttemptIds", "namedAuditInventory", "initialCredentialVersion", "refreshedCredentialVersion",
        "canonicalRequestVersion", "generationAuditEventIds", "reconciliationRejections", "revocationPublicationRejections",
        "grantPublicationReloadFailures"}
    if paired:
        fields = fields - {"goExampleSha256"} | {"nodeExampleSha256", "sdkDependenciesSha256"}
    require(set(value) == fields
        and all(value[k] is True for k in true_flags) and all(value[k] is False for k in false_flags), "Gmail SDK result shape differs")
    for key, expected in {"providerAttempts": count, "automaticRefreshes": 1, "initialCredentialVersion": 1,
            "refreshedCredentialVersion": 2, "canonicalRequestVersion": 3}.items():
        require(type(value[key]) is int and value[key] == expected, "Gmail SDK result count differs")
    require(type(value["reconciliationRejections"]) is int and value["reconciliationRejections"] in (0, 1),
        "Gmail SDK no-envelope reconciliation count differs")
    require(type(value["revocationPublicationRejections"]) is int and value["revocationPublicationRejections"] in (0, 1),
        "Gmail SDK no-envelope revocation publication count differs")
    require(type(value["grantPublicationReloadFailures"]) is int and value["grantPublicationReloadFailures"] in (0, 1),
        "Gmail SDK grant publication reload failure count differs")
    require(all(type(value[k]) is str and SHA256.fullmatch(value[k]) for k in ("dataPlaneBinaryDigest", "policyHash", "revokedPolicyHash"))
        and value["policyHash"] != value["revokedPolicyHash"]
        and type(value["nodeExampleSha256" if paired else "goExampleSha256"]) is str
        and HEX.fullmatch(value["nodeExampleSha256" if paired else "goExampleSha256"])
        and type(value["exampleSourceSha256"]) is dict and set(value["exampleSourceSha256"]) == set(profiles.SOURCES if paired else SOURCE_FILES)
        and all(type(v) is str and HEX.fullmatch(v) for v in value["exampleSourceSha256"].values()), "Gmail SDK artifact pins differ")
    if paired:
        require(value["nodeExampleSha256"] == profiles.NODE_SHA256 and type(value["sdkDependenciesSha256"]) is str
            and HEX.fullmatch(value["sdkDependenciesSha256"]), "Gmail SDK paired artifact pins differ")
    require(type(value["applicationIds"]) is list and len(value["applicationIds"]) == 2
        and len(set(value["applicationIds"])) == 2 and all(type(v) is str and UUID.fullmatch(v)
            for v in [value["credentialId"], value["ruleId"], *value["applicationIds"]]), "Gmail SDK retained identities differ")
    revisions = value["policyRevisions"]
    require(type(revisions) is dict and set(revisions) == {"accepted", "revoked"} and all(type(v) is int and v > 0 for v in revisions.values())
        and revisions["revoked"] == revisions["accepted"] + 1 and type(value["originalAccessExpiresAtEpochMs"]) is int
        and value["originalAccessExpiresAtEpochMs"] > 0 and type(value["refreshCompletedAtExpiry"]) is bool,
        "Gmail SDK original clock or revision evidence differs")
    completed = value["completed"]
    require(type(completed) is list and len(completed) == len(phases), "Gmail SDK process inventory differs")
    for phase, row in zip(phases, completed):
        positive = base_phase(phase, paired) in {"first", "refreshed"}
        require(type(row) is dict and set(row) == {"phase", "exitCode", "summary"} and row["phase"] == phase
            and type(row["exitCode"]) is int and row["exitCode"] == (0 if positive else 1)
            and row["summary"] == (SUMMARY if positive else None)
            and (row["summary"] is None or type(row["summary"].get("pages")) is int
                and type(row["summary"].get("messages_read")) is int and row["summary"].get("more_pages") is False),
            "Gmail SDK actual client result differs")
    observations_list = value["providerObservations"]
    require(type(observations_list) is list and len(observations_list) == 5, "Gmail SDK checkpoint inventory differs")
    for stage, row in zip(stages, observations_list):
        consent, refreshed, resources = stages[stage]
        require(type(row) is dict and set(row) == {"stage", "counts", "initialAccessExpiresAtEpochMs", "initialAccessExpired",
            "resourceGenerations", "cases", "refreshCompletedAtExpiry"} and row["stage"] == stage
            and row["initialAccessExpiresAtEpochMs"] == (value["originalAccessExpiresAtEpochMs"] if consent else None)
            and row["initialAccessExpired"] is (stage in {"expired", "refreshed"})
            and row["resourceGenerations"] == [1 + i // len(cases) for i in range(resources)]
            and all(type(v) is int for v in row["resourceGenerations"]) and row["cases"] == [cases[i % len(cases)] for i in range(resources)],
            "Gmail SDK checkpoint expiry or generations differ")
        require(row["refreshCompletedAtExpiry"] is (value["refreshCompletedAtExpiry"] if stage == "expired" else None),
            "Gmail SDK expiry refresh projection differs")
        refreshed = int(value["refreshCompletedAtExpiry"]) if stage == "expired" else refreshed
        expected = {"authorization_requests": consent, "authorization_codes_issued": consent, "authorization_code_exchanges": consent,
            "token_requests": consent + refreshed, "token_responses": consent + refreshed, "refresh_exchanges": refreshed,
            "identity_requests": consent, "resource_requests": resources, "resource_attempts": resources,
            "resource_gmail.messages.list": resources // 2, "resource_gmail.message.get": resources // 2}
        require(type(row["counts"]) is dict and all(type(v) is int for v in row["counts"].values())
            and row["counts"] == {k: v for k, v in expected.items() if v}, "Gmail SDK checkpoint exchange counts differ")
    requests = value["requests"]
    require(type(requests) is list and len(requests) == count, "Gmail SDK request evidence unavailable")
    for i, row in enumerate(requests):
        require(type(row) is dict and set(row) == REQUEST_KEYS and row["case"] == cases[i % len(cases)]
            and type(row["generation"]) is int and row["generation"] == 1 + i // len(cases)
            and all(type(row[k]) is str and SHA256.fullmatch(row[k]) for k in ("requestDigest", "operationDigest", "responseBodySha256"))
            and row["responseBodySha256"] == digest(fixture.selected_targets(paired)[row["case"]]["body"])
            and type(row["responseBodyBytes"]) is int and row["responseBodyBytes"] == len(fixture.selected_targets(paired)[row["case"]]["body"]),
            "Gmail SDK response commitment differs")
    require(len({r["requestDigest"] for r in requests}) == len({r["operationDigest"] for r in requests}) == count,
        "Gmail SDK result reused a request commitment")
    denials = value["negativeControls"]
    require(type(denials) is list and len(denials) == 4 * clients, "Gmail SDK negative inventory differs")
    denial_ids = []
    for phase, row in zip(phases[2 * clients:], denials):
        kind = NEGATIVE_KINDS[base_phase(phase, paired)]
        require(type(row) is dict and set(row) == {"phase", "providerAttemptsBefore", "providerAttemptsAfter", "auditEventType", "auditEventId"}
            and row["phase"] == phase and row["auditEventType"] == kind and all(type(row[k]) is int and row[k] == count
                for k in ("providerAttemptsBefore", "providerAttemptsAfter")), "Gmail SDK denial arrival evidence differs")
        require(row["auditEventId"] is None if kind is None else type(row["auditEventId"]) is str
            and SHA256.fullmatch(row["auditEventId"]), "Gmail SDK denial audit identity differs")
        if kind is not None:
            denial_ids.append(row["auditEventId"])
    require(len(set(denial_ids)) == 3 * clients, "Gmail SDK denial audit identities collide")
    for key, length, hash_count in (("durableAuditEventIds", 2 * count + 4, 2 * count),
            ("auditAttemptIds", count, count), ("generationAuditEventIds", count + 2, count)):
        rows = value[key]
        require(type(rows) is list and len(rows) == length
            and all(type(v) is str and (SHA256.fullmatch(v) or UUID.fullmatch(v)) for v in rows)
            and len(set(rows)) == length and sum(bool(SHA256.fullmatch(v)) for v in rows) == hash_count,
            "Gmail SDK durable evidence identities differ")
    inventory = value["namedAuditInventory"]
    expected = {START: count, RELEASE: count, CONNECT: count + clients, DENIED: 2 * clients, RELOAD: 2,
        "credential.oauth_connected": 1, "credential.oauth_refreshed": 1}
    rejected_count = value["reconciliationRejections"] + value["revocationPublicationRejections"]
    if rejected_count:
        expected[LEASE_REJECT] = rejected_count
    if value["grantPublicationReloadFailures"]:
        expected[RELOAD_FAILED] = 1
    require(type(inventory) is dict and set(inventory) == set(expected) | {LEASE}
        and all(type(v) is int for v in inventory.values()) and all(inventory[k] == v for k, v in expected.items())
        and 1 <= inventory[LEASE] <= 128, "Gmail SDK named audit inventory differs")
    return True


def run_checks(args):
    check = None
    try:
        require(args.control_base == args.operator_origin == base.fixture.CONTROL_ORIGIN
            and args.management_base == "http://127.0.0.1:9091"
            and args.proxy_url == fixture_proxy(getattr(args, "browser_permission", False))[0]
            and args.ca_file == TRUST_FILES["inner"] and args.proxy_ca_file == TRUST_FILES["outer"]
            and args.combined_ca_file == TRUST_FILES["combined"], "Gmail SDK fixed endpoint or trust path differs")
        paired = getattr(args, "sdk_pair", False)
        selected_cases(paired)
        require(not (paired and getattr(args, "browser_permission", False)), "paired browser mode refused")
        require((args.expected_go_sha256 is None and type(args.expected_dependencies_sha256) is str
            and HEX.fullmatch(args.expected_dependencies_sha256)) if paired else
            (type(args.expected_go_sha256) is str and HEX.fullmatch(args.expected_go_sha256)
                and getattr(args, "expected_dependencies_sha256", None) is None), "Gmail SDK selected artifact pin differs")
        require(type(args.expected_binary_sha256) is str and SHA256.fullmatch(args.expected_binary_sha256)
            and type(args.timeout_seconds) is int and 120 <= args.timeout_seconds <= 180, "Gmail SDK artifact pin or deadline differs")
        base.fixture.assert_isolated_network(); base.read_google_marker(args.google_fixture_marker_file)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = GmailSdkCheck(args)
        return check.run()
    except Exception as error:
        paired = getattr(args, "sdk_pair", False) is True
        phase = check.phase if check is not None and check.phase in ("startup", "revoke", "browser_permission", *selected_phases(paired)) else "startup"
        return {"schema": profiles.CHECK_SCHEMA if paired else SCHEMA, "ok": False, "syntheticOnly": True, "realGoogleVerified": False,
            "productionReady": False, "phase": phase,
            "failureSite": failure_site(error, Path(__file__).resolve().parents[1]),
            "error": "acceptance_check_failed" if isinstance(error, CheckFailure) else "acceptance_internal_failure"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "google-fixture-marker-file", "run-claim-file", "proxy-ca-file", "combined-ca-file"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--browser-permission", action="store_true")
    parser.add_argument("--sdk-pair", action="store_true")
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise CheckFailure("Gmail SDK process deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 180))
    try:
        result = run_checks(args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps({"type": "result", "result": result} if args.browser_permission else result, sort_keys=True), flush=True)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
