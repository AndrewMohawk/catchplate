#!/usr/bin/env python3
"""One-shot ordinary Requests Gmail job in the isolated synthetic fixture.

Uses real consent/callback, catalog writes, CONNECT, and durable audit helpers.
Never obtains a provider token, launches services, retries uncertain requests,
or changes refresh timing. The fixed HTTP loopback proxy is not evidence about
an HTTPS outer proxy, a Google SDK, the rendered UI, or a real Google account.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import signal
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from requests.adapters import HTTPAdapter

from scripts import check_operator_google_refresh as base
from scripts import operator_gmail_job_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import CheckFailure, SHA256, require, token_file


PROXY = "http://127.0.0.1:9090"
ORIGIN = "https://gmail.googleapis.com"
CREATE_PATH = PREFIX + "/access-rules/gmail-read"
CASES = ("list_page_1", "list_page_2", "message_full", "message_metadata")
STAGES = {"fresh": (0, 0, 0), "connected": (1, 0, 0),
          "first": (1, 0, 4), "expired": (1, 0, 4), "refreshed": (1, 1, 8)}
MAX_BODY = 65536  # This finite fixture is far below the signed 1 MiB limit.


def digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def require_bundle(catalog):
    bundles = catalog.get("capabilities", {}).get("operation_bundles")
    require(isinstance(bundles, list), "Gmail bundle capability unavailable")
    matches = [item for item in bundles if isinstance(item, dict) and item.get("operation_bundle") == "gmail_read_v1"]
    require(len(matches) == 1, "Gmail bundle capability missing or duplicated")
    item = matches[0]
    require(all(item.get(key) == value for key, value in {
        "create_path": CREATE_PATH, "credential_type": "google_oauth", "permission_preset": "gmail_readonly",
        "api_origin": ORIGIN, "methods": ["GET"],
        "paths": [base.fixture.GMAIL_PATH, base.fixture.GMAIL_PATH + "/{message_id}"],
        "query_mode": "orderedFormV1", "age_policy": {"mode": "unrestricted"},
        "response_mode": "gmail_read_json_v1"}.items()), "Gmail bundle capability contract differs")
    contract = item.get("response_contract", {})
    require(contract.get("mode") == "gmailReadJsonV1" and contract.get("success_status_codes") == [200]
            and contract.get("content_types") == ["application/json"]
            and contract.get("body_presence") == "required"
            and contract.get("unlisted_header_policy") == "discardUnselectedV1",
            "Gmail response capability differs")


def require_rule(rule, *, application_id, credential_id):
    expected = {"operation_bundle": "gmail_read_v1", "query_mode": "orderedFormV1",
        "age_policy": {"mode": "unrestricted"}, "response_mode": "gmail_read_json_v1",
        "credential_input": "insert", "methods": ["GET"], "request_fields": [], "response_fields": [],
        "allowed_headers": ["accept", "user-agent", "x-goog-api-client"],
        "application_id": application_id, "credential_id": credential_id,
        "upstream_url": ORIGIN + base.fixture.GMAIL_PATH, "status": "active"}
    require(isinstance(rule, dict) and all(rule.get(key) == value for key, value in expected.items())
            and "request_body_mode" not in rule and "placeholder" not in rule,
            "saved Gmail rule differs from the explicit no-age ordered read bundle")


class ProxyBearerAdapter(HTTPAdapter):
    """App token is supplied to CONNECT only, never to origin request headers."""

    def __init__(self, token, ca_file):
        require(isinstance(token, str) and base.re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token),
                "application token shape differs")
        self._proxy_token, self._ca_file = token, str(ca_file)
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1, pool_block=True)

    def proxy_headers(self, proxy):
        require(proxy == PROXY, "Requests proxy destination differs")
        return {"Proxy-Authorization": "Bearer " + self._proxy_token}

    def send(self, request, **kwargs):
        parsed = urlsplit(request.url)
        require(parsed.scheme == "https" and parsed.netloc == "gmail.googleapis.com"
                and parsed.path.startswith(base.fixture.GMAIL_PATH) and not parsed.fragment
                and kwargs.get("proxies") == {"https": PROXY}
                and kwargs.get("verify") == self._ca_file and kwargs.get("stream") is True,
                "Requests fixed proxy, target, or verification boundary differs")
        require(not {name.lower() for name in request.headers}.intersection({"proxy-authorization",
            "authorization", "cookie", "x-catchplate-admin-token"}), "origin request contains identity material")
        return super().send(request, **kwargs)


def requests_session(token, ca_file):
    session = requests.Session()
    session.trust_env = False  # No proxy environment, netrc, or CA environment.
    session.verify = str(ca_file)
    session.proxies = {"https": PROXY}
    for adapter in session.adapters.values():
        adapter.close()
    session.adapters.clear()  # No direct HTTP/other-origin fallback.
    session.mount(ORIGIN + "/", ProxyBearerAdapter(token, ca_file))
    # Leave the actual Requests defaults untouched; their compression offer is
    # removed by the signed gate policy, not by this workload.
    require(set(name.lower() for name in session.headers) == {"user-agent", "accept-encoding", "accept", "connection"}
            and session.headers["Accept"] == "*/*" and "gzip" in session.headers["Accept-Encoding"]
            and session.headers["User-Agent"].startswith("python-requests/"), "Requests default headers differ")
    return session


def request_commitments(prepared, *, scope, credential_id, generation):
    """Independent expected canonical-v3 recipe from the actual client request.

    No decision endpoint or provider-secret API is consulted. The isolated
    loopback CONNECT peer supplies client_ip; normal Rust serializes version as
    a string. Empty GET has no physical Content-Length in this Requests job.
    """
    parts = urlsplit(prepared.url)
    headers = {name.lower(): value for name, value in prepared.headers.items()}
    require(prepared.method == "GET" and prepared.body in (None, b"", "")
            and parts.scheme == "https" and parts.netloc == "gmail.googleapis.com"
            and set(headers) == {"user-agent", "accept-encoding", "accept", "connection"}
            and headers["connection"] == "keep-alive" and "gzip" in headers["accept-encoding"],
            "ordinary Requests input cannot be joined to canonical-v3")
    operation = {"operation": "gmail.messages.list", "gmailUser": "me"}
    if parts.path != base.fixture.GMAIL_PATH:
        identifier = parts.path.removeprefix(base.fixture.GMAIL_PATH + "/")
        require(identifier in fixture.MESSAGE_IDS, "job detail ID did not originate in its pages")
        operation = {"operation": "gmail.message.get", "gmailUser": "me", "messageId": identifier}
    canonical = {"v": 3, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": str(generation), "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "gmail.googleapis.com",
            "path": parts.path, "query": [list(pair) for pair in parse_qsl(parts.query, keep_blank_values=True,
                encoding="utf-8", errors="strict")], "query_mode": "orderedFormV1",
            "query_wire": parts.query if "?" in prepared.url else None,
            "headers": {"accept": headers["accept"], "user-agent": headers["user-agent"], "host": "gmail.googleapis.com"},
            "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(), "discard_headers": ["accept-encoding"]},
        "operation": operation}
    operation_view = {key: value for key, value in canonical.items() if key not in {"v", "client_ip"}}
    return digest(canonical), digest(operation_view)


def response_commitment(status, fields, body, *, case, policy_hash, expected):
    require(status == 200 and body == fixture.TARGETS[case]["body"], "Gmail job status or exact body differs")
    lowered = [name.lower() for name, _ in fields]
    require(len(fields) <= 64 and len(lowered) == len(set(lowered)) and len(str(fields)) <= 16384,
            "Gmail job response headers ambiguous or unbounded")
    headers = dict((name.lower(), value) for name, value in fields)
    body_hash = "sha256:" + hashlib.sha256(body).hexdigest()
    require(headers.get("x-catchplate-policy-hash") == policy_hash
            and headers.get("x-catchplate-response-body-sha256") == body_hash
            and (headers.get("x-catchplate-request-digest"), headers.get("x-catchplate-operation-digest")) == expected
            and not set(headers).intersection({"server", "date", "cache-control", "content-encoding"}),
            "Gmail canonical-v3 commitment or discarded response metadata differs")
    return {"case": case, "requestDigest": expected[0], "operationDigest": expected[1],
        "responseBodySha256": body_hash, "responseBodyBytes": len(body)}


def observations(document, stage):
    """Closed job/provider evidence, including every attempted Gmail dispatch."""
    require(stage in STAGES and isinstance(document, dict)
            and document.get("schema") == "catchplate.privateGoogleObservations/v1", "Gmail observations unavailable")
    consent, refresh, resources = STAGES[stage]
    counts = document.get("counts", {})
    require(isinstance(counts, dict) and set(counts) == {"google", "x"} and counts["x"] == {}
            and isinstance(counts["google"], dict), "Gmail provider inventory differs")
    if stage == "expired":
        refresh = counts["google"].get("refresh_exchanges", 0)
        require(type(refresh) is int and refresh in (0, 1), "automatic refresh checkpoint differs")
    expected = {"authorization_requests": consent, "authorization_codes_issued": consent,
        "authorization_code_exchanges": consent, "token_requests": consent + refresh,
        "token_responses": consent + refresh, "refresh_exchanges": refresh, "identity_requests": consent,
        "resource_requests": resources, "resource_attempts": resources,
        "resource_gmail.messages.list": resources // 2, "resource_gmail.message.get": resources // 2}
    require(all(type(value) is int and value >= 0 for value in counts["google"].values())
            and {key: value for key, value in counts["google"].items() if value}
                == {key: value for key, value in expected.items() if value}, "Gmail exchange or operation counts differ")
    require(document.get("tokenLifetimes") == {"authorizationCodeExchangeSeconds": 90, "refreshExchangeSeconds": 300}
            and document.get("active") == {"authorizationCodes": 0, "grants": consent}, "Gmail lifetime or grant state differs")
    events = document.get("events")
    inventory = {"authorization_validated": consent, "authorization_code_issued": consent,
        "authorization_code_exchanged": consent, "identity_returned": consent, "tokens_issued": consent + refresh,
        "refresh_token_rotated": refresh, "resource_received": resources, "resource_authorized": resources}
    require(isinstance(events, list) and len(events) <= 24
            and all(isinstance(row, dict) and row.get("provider") == "google" and row.get("sequence") == index + 1
                and type(row.get("sequence")) is int and type(row.get("timestamp_epoch_ms")) is int
                for index, row in enumerate(events))
            and Counter(row.get("type") for row in events) == Counter({key: value for key, value in inventory.items() if value}),
            "Gmail provider event inventory differs")
    for row in events:
        kind = row["type"]
        if kind in {"authorization_validated", "authorization_code_issued"}:
            require(row.get("requested_scopes") == base.SCOPES, "Gmail consent scopes differ")
        if kind == "authorization_validated":
            require(row.get("outcome") == "success", "Gmail consent was not approved")
        if kind in {"authorization_code_exchanged", "tokens_issued", "refresh_token_rotated"}:
            require(row.get("granted_scopes") == base.SCOPES, "Gmail grant scopes differ")
        if kind == "authorization_code_exchanged":
            require(row.get("pkce") == "S256", "Gmail code exchange lacks PKCE")
        if kind == "identity_returned":
            require(row.get("malformed") is False, "Gmail verified identity differs")
    require([row.get("grant_type") for row in events if row["type"] == "tokens_issued"]
            == (["authorization_code"] if consent else []) + (["refresh_token"] if refresh else []),
            "Gmail token issuance origins differ")
    job = document.get("gmailJob", {})
    attempts = job.get("attempts")
    require(job.get("schema") == fixture.JOB_SCHEMA and job.get("maxAttempts") == 16
            and isinstance(attempts, list) and len(attempts) == resources, "Gmail finite job fixture unavailable")
    expiry = document.get("initialAccessExpiresAtEpochMs")
    require((type(expiry) is int and expiry > 0) if consent else expiry is None, "Gmail actual access expiry unavailable")
    require(document.get("initialAccessExpired") is (stage in {"expired", "refreshed"}), "Gmail expiry checkpoint differs")
    authorized = [row for row in events if row["type"] == "resource_authorized"]
    for index, attempt in enumerate(attempts):
        case, generation = CASES[index % 4], 1 + index // 4
        spec = fixture.TARGETS[case]
        require(isinstance(attempt, dict) and all(attempt.get(key) == value for key, value in {
            "ordinal": index + 1, "case": case, "method": "GET", "path": spec["path"], "rawQuery": spec["raw_query"],
            "authorized": True, "status": 200, "tokenGeneration": generation, "acceptEncodingAbsent": True}.items())
            and type(attempt.get("timestampEpochMs")) is int, "Gmail actual target, authorization or compression discard differs")
        event = authorized[index]
        operation = "gmail.messages.list" if index % 4 < 2 else "gmail.message.get"
        require(type(event.get("token_generation")) is int and event["token_generation"] == generation
                and event.get("operation") == operation, "Gmail resource generation or operation differs")
        require((event["timestamp_epoch_ms"] < expiry - 60000 and attempt["timestampEpochMs"] < expiry - 60000)
                if generation == 1 else (event["timestamp_epoch_ms"] >= expiry + 1000 and attempt["timestampEpochMs"] >= expiry + 1000),
                "Gmail job did not straddle the actual access-token expiry")
    result = {"stage": stage, "counts": dict(sorted(counts["google"].items())),
        "initialAccessExpiresAtEpochMs": expiry, "initialAccessExpired": document["initialAccessExpired"],
        "resourceGenerations": [row["token_generation"] for row in authorized],
        "cases": [row["case"] for row in attempts]}
    if stage == "expired":
        result["refreshCompletedAtExpiry"] = bool(refresh)
    return result


def generation_evidence(events, scope, credential_id, commitments):
    connected = [row for row in events if row.get("event_type") == "credential.oauth_connected"]
    refreshed = [row for row in events if row.get("event_type") == "credential.oauth_refreshed"]
    starts = [row for row in events if row.get("event_type") == "data_plane.credential.release_started"]
    terminals = [row for row in events if row.get("event_type") == "data_plane.response.released"]
    require(len(connected) == len(refreshed) == 1 and len(starts) == len(terminals) == len(commitments) == 8,
            "Gmail durable generation or release inventory differs")
    require(connected[0]["event"].get("credential_id") == credential_id
            and connected[0]["event"].get("credential_version") == 1, "Gmail initial persisted generation differs")
    refresh = refreshed[0]["event"]
    require(all(refresh.get(key) == value for key, value in {"credential_id": credential_id, "provider": "google",
        "previous_credential_version": 1, "credential_version": 2, "refresh_token_rotated": True, "scopes": base.SCOPES}.items()),
        "Gmail automatic refresh did not persist exactly one new generation")
    expected = {(item["requestDigest"], item["operationDigest"]): item for item in commitments}
    require(len(expected) == 8, "Gmail wire attempts reused a canonical commitment")
    observed = set()
    starts_by_attempt = {row["event"].get("attempt_id"): row for row in starts}
    require(len(starts_by_attempt) == 8, "Gmail release-start identities collide")
    for row in terminals:
        event = row["event"]
        key = (event.get("request_digest"), event.get("operation_digest"))
        require(key in expected and key not in observed, "Gmail durable release lacks its exact wire commitment")
        observed.add(key)
        item = expected[key]
        start = starts_by_attempt.get(event.get("attempt_id"), {}).get("event", {})
        require(start.get("credential_ref") == credential_id and type(start.get("credential_version")) is int
                and start["credential_version"] == item["generation"]
                and all(tuple(source.get(key) for key in ("principal_id", "route_id", "policy_hash")) == scope
                    and source.get("method") == "GET" for source in (start, event))
                and (start.get("request_digest"), start.get("operation_digest")) == key
                and event.get("response_body_sha256") == item["responseBodySha256"]
                and event.get("response_body_bytes") == item["responseBodyBytes"],
                "Gmail same-account/app generation, attempt or response bytes do not join")
    return {"initialCredentialVersion": 1, "refreshedCredentialVersion": 2, "canonicalRequestVersion": 3,
        "generationAuditEventIds": sorted(row["id"] for row in connected + refreshed + starts)}


class GmailJobCheck(base.GoogleRefreshCheck):
    def observe(self, stage):
        status, document = self.json_request(self.upstream, base.fixture.OBSERVATIONS_PATH, context=self.upstream_ca)
        require(status == 200, "Gmail fixture observations failed")
        result = observations(document, stage)
        self.provider_observations.append(result)
        return result

    def send(self, session, *, method, path, params, case=None, scope=None, credential_id=None, generation=None):
        prepared = session.prepare_request(requests.Request(method, ORIGIN + path, params=list(params)))
        if case is not None:
            spec = fixture.TARGETS[case]
            require(prepared.url == ORIGIN + spec["path"] + "?" + spec["raw_query"],
                    "Requests did not preserve the finite job's ordered query target")
            expected = request_commitments(prepared, scope=scope, credential_id=credential_id, generation=generation)
        try:
            response = session.send(prepared, allow_redirects=False, stream=True,
                timeout=(self.timeout(), self.timeout()), verify=str(self.args.ca_file), proxies={"https": PROXY})
            try:
                fields = list(response.raw.headers.iteritems())
                body = response.raw.read(MAX_BODY + 1, decode_content=False)
                require(len(body) <= MAX_BODY, "Gmail job response exceeds finite bound")
                self.clean(str(fields).encode("utf-8")); self.clean(body)
                if case is None:
                    denial = json.loads(body)
                    require(response.status_code == 403 and denial.get("allowed") is False and denial.get("action") == "deny",
                            "wrong-method job control was not denied")
                    return None
                item = response_commitment(response.status_code, fields, body, case=case,
                    policy_hash=self.policy_hash, expected=expected)
                item["generation"] = generation
                self.wire_commitments.append(item)
                return json.loads(body)
            finally:
                response.close()
        except requests.RequestException:
            # Requests errors may contain URLs or proxy details. Retain only a
            # fixed stage error, never the exception's arbitrary representation.
            raise CheckFailure("normal Requests Gmail transport failed") from None

    def job(self, session, scope, credential_id, generation):
        def get(case, path, params):
            result = self.send(session, method="GET", path=path, params=params, case=case,
                scope=scope, credential_id=credential_id, generation=generation)
            self.successes.append(scope)
            return result
        first = get("list_page_1", base.fixture.GMAIL_PATH, fixture.LIST_PARAMS)
        cursor = first.get("nextPageToken")
        require(cursor == fixture.PAGE_TOKEN, "first page cursor missing or changed")
        second = get("list_page_2", base.fixture.GMAIL_PATH, (*fixture.LIST_PARAMS, ("pageToken", cursor)))
        require("nextPageToken" not in second, "finite inbox pagination did not terminate")
        identifiers = [row["id"] for page in (first, second) for row in page["messages"]]
        require(identifiers == list(fixture.MESSAGE_IDS), "returned inbox message IDs differ")
        # Paths derive from the actual returned IDs, not a preselected single
        # message route. The fixture independently requires these exact bytes.
        for case, identifier, params in (("message_full", identifiers[0], fixture.FULL_PARAMS),
                ("message_metadata", identifiers[1], fixture.METADATA_PARAMS)):
            detail = get(case, base.fixture.GMAIL_PATH + "/" + identifier, params)
            require(detail["id"] == identifier, "message get did not return the selected listed ID")

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == 1 and all(not initial[key] and initial["limits"][key]["retained"] == 0
                for key in COLLECTIONS), "Gmail job requires an empty fresh catalog")
        require_bundle(initial)
        self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("fresh_gmail_job_catalog")
        self.observe("fresh")  # Refuses the old single-URL fixture before consent.
        credential = self.connect_account(initial)
        self.observe("connected")
        application, self.client_token, _ = self.mutate("/applications",
            {"name": self.run_id + "-inbox", "token_lifetime_seconds": 3600}, collection="applications",
            result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        unassigned, wrong_token, _ = self.mutate("/applications",
            {"name": self.run_id + "-unassigned", "token_lifetime_seconds": 3600}, collection="applications",
            result_key="application", event="operator_catalog.application.created", creates=True, token=True)
        rule, _, _ = self.mutate("/access-rules/gmail-read", {"name": self.run_id + "-read-mail",
            "application_id": application["id"], "credential_id": credential["id"],
            "operation_bundle": "gmail_read_v1", "credential_input": "insert", "age_policy": {"mode": "unrestricted"}},
            collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.created",
            creates=True, authority_changed=True)
        require_rule(rule, application_id=application["id"], credential_id=credential["id"])
        pinned, _ = self.wait_catalog_loaded("gmail_job_rule_loaded")
        require_rule(self.resource(pinned, "access_rules", rule["id"]), application_id=application["id"], credential_id=credential["id"])
        require(len(pinned["credentials"]) == 1 and len(pinned["applications"]) == 2 and len(pinned["access_rules"]) == 1
                and self.resource(pinned, "applications", unassigned["id"]).get("access_status") == "unassigned",
                "Gmail wrong-app control is not a valid unassigned identity")
        scope = (application["principal_id"], rule["route_id"], self.policy_hash)
        lease_scope = {"purpose": "dispatchSecret", "principal_id": scope[0], "route_id": scope[1],
            "policy_hash": scope[2], "credential_id": credential["id"], "data_plane_binary_digest": self.args.expected_binary_sha256}
        self.tunnel(wrong_token, expected_status=403)
        self.observe("connected"); features.record_negative_phase(self, "valid_unassigned_application", lease_scope)
        base.no_dispatch_effects(self.audit())
        with requests_session(self.client_token, self.args.ca_file) as session:
            self.send(session, method="POST", path=base.fixture.GMAIL_PATH, params=[])
            self.observe("connected"); features.record_negative_phase(self, "wrong_method", lease_scope)
            base.no_dispatch_effects(self.audit())
            self.unchanged(pinned)
            self.results.append("valid_unassigned_app_and_wrong_method_denied_without_provider_or_lease_effects")
            self.job(session, scope, credential["id"], 1)
            first = self.observe("first")
            self.results.append("normal_requests_ordered_repeated_query_list_pagination_and_returned_id_reads")
            remaining = (first["initialAccessExpiresAtEpochMs"] + 1000 - time.time_ns() // 1_000_000) / 1000
            require(0 < remaining <= 91 and self.deadline - time.monotonic() > remaining + 15,
                    "real token expiry cannot fit the bounded Gmail job window")
            until = time.monotonic() + remaining
            while time.monotonic() < until:
                time.sleep(max(0.0, min(1.0, until - time.monotonic(), self.timeout())))
            expired = self.observe("expired")
            self.unchanged(pinned)
            self.job(session, scope, credential["id"], 2)
        self.observe("refreshed")
        self.unchanged(pinned)
        audit_ids, attempts = features.verify_audit(self)
        generations = generation_evidence(self.audit(), scope, credential["id"], self.wire_commitments)
        self.observe("refreshed")
        self.results.append("same_account_and_app_continue_after_actual_expiry_with_one_automatic_refresh")
        self.results.append("eight_wire_bodies_canonical_v3_and_durable_attempts_join_without_provider_secret_disclosure")
        result = {"ok": True, "schema": "catchplate.operatorGmailJobCheck/v1", "syntheticOnly": True,
            "realGoogleVerified": False, "browserUiVerified": False, "productionReady": False, "hardwareVerified": False,
            "checks": self.results, "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            "requestsVersion": requests.__version__, "credentialId": credential["id"],
            "applicationIds": [application["id"], unassigned["id"]], "ruleId": rule["id"],
            "refreshCompletedAtExpiry": expired["refreshCompletedAtExpiry"],
            "providerObservations": self.provider_observations, "wireCommitments": self.wire_commitments,
            "durableAuditEventIds": audit_ids, "auditedRequestAttemptIds": attempts, **generations}
        serialized = json.dumps(result, sort_keys=True)
        self.clean(serialized.encode())
        require(all(value not in serialized for value in self.transient_values), "OAuth browser values escaped into job evidence")
        return result


def run_checks(args):
    check = None
    try:
        require(args.control_base == base.fixture.CONTROL_ORIGIN and args.operator_origin == base.fixture.CONTROL_ORIGIN
                and args.management_base == "http://127.0.0.1:9091" and args.proxy_url == PROXY,
                "Gmail job fixed isolated endpoints differ")
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256)
                and type(args.timeout_seconds) is int and 120 <= args.timeout_seconds <= 180,
                "Gmail job artifact pin or deadline differs")
        base.fixture.assert_isolated_network()
        base.read_google_marker(args.google_fixture_marker_file)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = GmailJobCheck(args)
        return check.run()
    except Exception as error:
        return {"ok": False, "schema": "catchplate.operatorGmailJobCheck/v1", "syntheticOnly": True,
            "realGoogleVerified": False, "productionReady": False, "checks": list(check.results) if check else [],
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
        raise CheckFailure("Gmail job exceeded its process deadline")
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
