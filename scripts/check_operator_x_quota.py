#!/usr/bin/env python3
"""Real ordinary X quota lane; never seeds credentials or calls quota APIs.

Two actual applications share four posting attempts. A runner-owned retained
restart, genuine token expiry/refresh, and disconnect/reconsent keep the same
account-day budget. All SDK entrypoints are unchanged. This proves only the
separately pinned network-none synthetic fixture, not X or public deployment.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_x_post as base
from scripts.check_operator_demo import CheckFailure, SHA256, require, token_file
from scripts.check_operator_key_replacement import authority_projection

SCHEMA = "catchplate.privateXQuotaCheck/v1"
PROVIDER_SCHEMA = "catchplate.privateXQuotaProvider/v1"
DAY_MS = 86_400_000
PHASES = ("node:a_first", "python:b_first", "go:a_first", "node:b_refreshed",
    "python:a_exhausted", "go:b_exhausted", "node:alias_exhausted")
QUOTA_DESCRIPTOR = {"schema": "catchplate.operatorXPostAttemptQuota/v1", "field": "daily_post_attempt_limit",
    "period": "utc_day", "scope": "verified_x_account", "unit": "posting_attempt", "minimum": 1,
    "maximum": 1000000000}
RESERVED, CLAIMED = "operator_x.quota.reserved", "operator_x.quota.claimed"
DENIED = "data_plane.request.denied"
AUDIT_EXACT = {base.START: 7, base.RELEASE: 4, DENIED: 3, base.CONNECT: 7, RESERVED: 4, CLAIMED: 4,
    "operator_catalog.application.created": 2, "operator_catalog.access_rule.x_post_created": 3,
    **{base.LIFECYCLE + suffix: count for suffix, count in (("configuration_saved", 1), ("consent_started", 2),
        ("exchange_claimed", 2), ("account_connected", 2), ("account_refreshed", 1), ("disconnect_fenced", 2), ("disconnected", 2))}}
RECEIPT_FIELDS = {"schema", "reservation_id", "bucket_key", "utc_day", "expires_at_epoch_ms", "binding_digest"}
BINDING_FIELDS = {"principal_id", "route_id", "credential_id", "credential_version", "credential_metadata_digest",
    "policy_hash", "request_digest", "operation_digest", "attempt_nonce", "recipient_digest",
    "request_binding_digest", "expires_at_epoch_ms"}
QUOTA_TOKEN = re.compile(rb"synthetic-x-quota-a[12]-(?:access|refresh)-g[12]-[A-Za-z0-9_-]{43}")
encoded, digest, document = base.encoded, base.digest, base.document


def exact(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def account_digest(subject):
    require(type(subject) is str and re.fullmatch(r"[1-9][0-9]{0,19}", subject), "verified X subject differs")
    return digest(b"x\0" + subject.encode("ascii"))


def commitments(client, scope, credential_id, generation, subject):
    require(client in base.profiles.CLIENTS and type(generation) is int and generation in (1, 2)
        and len(scope) == 3 and SHA256.fullmatch(scope[2]) and base.UUID.fullmatch(credential_id),
        "quota canonical authority differs")
    raw = base.profiles.post_body(client)
    canonical = {"v": 2, "principal": scope[0], "client_ip": "127.0.0.1", "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": str(generation), "policy_hash": scope[2],
        "request": {"method": "POST", "scheme": "https", "authority": "api.x.com", "path": "/2/tweets",
            "query": [], "headers": base.profiles.canonical_headers(client), "body_sha256": digest(raw),
            "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "tweets.write", "providerAccount": account_digest(subject)}}
    return digest(canonical), digest({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}})


def validate_provider(value, *, posts, consents, refreshed, cleaned, anchor, expired):
    """Closed arrival oracle, including all issued token families and cleanup."""
    require(type(posts) is int and 0 <= posts <= 4 and type(consents) is int and consents in (0, 1, 2)
        and type(cleaned) is int and 0 <= cleaned <= consents and type(refreshed) is bool
        and type(expired) is bool and (not refreshed or consents >= 1), "quota observation phase differs")
    fields = (base.OBSERVATION_KEYS - {"issuedGenerations"}) | {"issuedTokenFamilies"}
    require(type(value) is dict and set(value) == fields and value["schema"] == PROVIDER_SCHEMA
        and value["syntheticOnly"] is True and value["terminal"] == "running" and value["overflowed"] is False,
        "quota provider envelope differs")
    counts = {"authorize": consents, "code": consents, "refresh": int(refreshed),
        "identity": consents + int(refreshed), "revoke": (4 if cleaned >= 1 else 0) + (2 if cleaned == 2 else 0),
        "posts": posts, "rejected": 0}
    counts["total"] = sum(counts.values())
    exact(value["counts"], counts, "extra quota provider contact or retry")
    families = ([{"alias": 1, "generation": 1}] if consents else [])
    if refreshed:
        families.append({"alias": 1, "generation": 2})
    if consents == 2:
        families.append({"alias": 2, "generation": 1})
    exact(value["issuedTokenFamilies"], families, "quota token family changed")
    exact(value["tokenLifetimes"], {"initial": 120, "refreshed": 600}, "quota token lifetime changed")
    require(value["refreshAfterInitialExpiry"] is refreshed and value["initialAccessExpired"] is expired
        and value["cleanupComplete"] is (consents > 0 and cleaned == consents), "quota lifetime/cleanup observation differs")
    issued, expiry = value["initialAccessIssuedAtEpochMs"], value["initialAccessExpiresAtEpochMs"]
    require((type(issued) is int and type(expiry) is int and type(anchor) is int
        and 0 < anchor <= issued and expiry == issued + 120000) if consents else issued is expiry is None,
        "original quota token expiry differs")
    require(type(value["posts"]) is list and len(value["posts"]) == posts, "quota post count differs")
    for index, row in enumerate(value["posts"]):
        ordinal, client = index + 1, base.profiles.CLIENTS[index % 3]
        generation = 1 if ordinal <= 3 else 2
        raw, response = base.profiles.post_body(client), base.response_body(ordinal)
        require(type(row) is dict and set(row) == base.POST_KEYS | {"alias"}, "quota post shape differs")
        expected = {"ordinal": ordinal, "client": client, "case": "success", "alias": 1,
            "generation": generation, "requestBodySha256": digest(raw), "requestBodyBytes": len(raw),
            "requestHeaders": base.profiles.provider_headers(client), "responseBodySha256": digest(response),
            "responseBytes": len(response), "status": 201, "postId": str(9000000000000000000 + ordinal),
            "providerCredentialMatched": True, "proxyAuthorizationPresent": False}
        exact({k: v for k, v in row.items() if k != "timestampEpochMs"}, expected, "quota literal provider bytes differ")
        timestamp = row["timestampEpochMs"]
        require(type(timestamp) is int and timestamp >= issued
            and (timestamp < anchor + 60000 if generation == 1 else timestamp >= expiry + 1000),
            "quota SDK wave crossed original lifetime boundary")
    revocations = value["revocations"]
    expected = [(1, g, h) for g in (1, 2) for h in ("access_token", "refresh_token")] if cleaned else []
    if cleaned == 2:
        expected += [(2, 1, h) for h in ("access_token", "refresh_token")]
    require(type(revocations) is list and all(type(row) is dict and set(row) == {
        "alias", "generation", "tokenTypeHint", "originalClientVerified"}
        and type(row["alias"]) is int and type(row["generation"]) is int
        and row["originalClientVerified"] is True for row in revocations)
        and Counter((r["alias"], r["generation"], r["tokenTypeHint"]) for r in revocations) == Counter(expected),
        "quota original-client cleanup roster differs")
    return value


def validate_sdk(phase, code, stdout, stderr, ordinal=None):
    require(phase in PHASES, "quota SDK phase differs")
    client = phase.split(":")[0]
    if ordinal is not None:
        base.validate_client_result(client + ":first", code, stdout, stderr, str(9000000000000000000 + ordinal))
    else:
        require(type(code) is int and code == 2 and stdout == b"" and type(stderr) is bytes and len(stderr) <= 8192,
            "quota denial did not preserve SDK no-replay failure")
        if client == "node":
            exact(document(stderr), {"ok": False, "operation": "create-post", "outcome": "unknown",
                "mayHaveBeenPosted": True, "automaticRetryAllowed": False, "httpStatus": 429,
                "error": base.profiles.NODE_UNKNOWN}, "quota Node denial differs")
        else:
            require(stderr == base.profiles.FAILURE_MESSAGES[client], "quota SDK diagnostic differs")
    return {"phase": phase, "exitCode": code, "confirmed": ordinal is not None}


def validate_quota_events(events, starts, *, subject, day):
    """Actual durable receipt/binding join, not a timing or counter inference."""
    base.features.audit_cutoff(events)
    selected = [row for row in events if row["event_type"] in {RESERVED, CLAIMED}]
    require(Counter(row["event_type"] for row in selected) == {RESERVED: 4, CLAIMED: 4},
        "quota must reserve and irreversibly claim exactly four attempts")
    bucket = digest({"provider": "x", "subject": subject, "operation": "tweets.write", "utc_day": day})
    pairs = {}
    for row in selected:
        value, claimed = row["event"], row["event_type"] == CLAIMED
        require(type(value) is dict and set(value) == RECEIPT_FIELDS | {"binding"} | ({"claimed_at_epoch_ms"} if claimed else set()),
            "quota durable receipt shape differs")
        binding = value["binding"]
        require(type(binding) is dict and set(binding) == BINDING_FIELDS and digest(binding) == value["binding_digest"]
            and value["schema"] == "catchplate.operatorXPostingQuota" + ("Claim/v1" if claimed else "Reservation/v1")
            and type(value["utc_day"]) is int and value["utc_day"] == day and value["bucket_key"] == bucket
            and type(value["reservation_id"]) is str and base.UUID.fullmatch(value["reservation_id"])
            and type(value["expires_at_epoch_ms"]) is int
            and value["expires_at_epoch_ms"] == binding["expires_at_epoch_ms"]
            and day * DAY_MS < value["expires_at_epoch_ms"] <= (day + 1) * DAY_MS,
            "quota durable binding/day/account differs")
        attempt = binding["attempt_nonce"]
        require(attempt in starts, "quota claim lacks actual request start")
        start = starts[attempt]
        fixed = {"principal_id": start["principal_id"], "route_id": start["route_id"],
            "credential_id": start["credential_ref"], "credential_version": start["credential_version"],
            "policy_hash": start["policy_hash"], "request_digest": start["request_digest"],
            "operation_digest": start["operation_digest"], "attempt_nonce": start["attempt_id"]}
        exact({k: binding[k] for k in fixed}, fixed, "quota claim rebound to another SDK attempt")
        require(all(type(binding[k]) is str and SHA256.fullmatch(binding[k]) for k in
            ("credential_metadata_digest", "recipient_digest", "request_binding_digest")), "quota cryptographic binding missing")
        pair = pairs.setdefault(value["reservation_id"], {})
        require(claimed not in pair, "quota receipt replay")
        pair[claimed] = value
        if claimed:
            require(type(value["claimed_at_epoch_ms"]) is int
                and day * DAY_MS <= value["claimed_at_epoch_ms"] < value["expires_at_epoch_ms"],
                "quota claim crossed original day/deadline")
    require(len(pairs) == 4 and all(set(pair) == {False, True} for pair in pairs.values()), "quota reservation/claim pair missing")
    for pair in pairs.values():
        exact({k: v for k, v in pair[True].items() if k not in {"schema", "claimed_at_epoch_ms"}},
            {k: v for k, v in pair[False].items() if k != "schema"}, "quota claim changed reservation")
    nonces = [pair[True]["binding"]["attempt_nonce"] for pair in pairs.values()]
    require(len(set(nonces)) == 4, "quota attempt charged twice")
    return sorted(nonces), sorted(pairs), bucket


class XQuotaCheck(base.XPostCheck):
    def __init__(self, args):
        super().__init__(args)
        # The public restart rendezvous uses a canonical UUID, not the legacy
        # generic checker's descriptive resource-name prefix.
        self.run_id = str(uuid.uuid4())
        self.alias, self.cleaned, self.refreshed = 1, 0, False
        self.contexts, self.lifecycle_records, self.disconnects = [], [], []
        self.restart = None
        self.day = time.time_ns() // 1_000_000 // DAY_MS
        require((self.day + 1) * DAY_MS - time.time_ns() // 1_000_000 > 180000,
            "quota fixture cannot span an actual UTC boundary")

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        require(QUOTA_TOKEN.search(content) is None, "quota provider secret escaped")

    def observe(self, posts, *, connected=True, refreshed=False, disconnected=False, expired=False):
        status, _, raw = self.exchange(self.upstream, "/__test__/observations")
        require(status == 200, "quota provider observation unavailable")
        value = validate_provider(document(raw), posts=posts, consents=self.alias if connected else 0,
            refreshed=refreshed, cleaned=self.cleaned, anchor=getattr(self, "callback_anchor", None), expired=expired)
        previous = [row for row in self.provider_checkpoints if row["initialAccessExpiresAtEpochMs"] is not None]
        require(not previous or all(value[k] == previous[0][k] for k in
            ("initialAccessIssuedAtEpochMs", "initialAccessExpiresAtEpochMs")), "quota restart/reconnect reset initial expiry")
        self.provider_checkpoints.append(value)
        require(len(self.provider_checkpoints) <= 24, "quota observation budget exceeded")
        self.arrivals = value["posts"]
        return value

    def limited_rule(self, app, suffix):
        current = self.catalog()
        capability = current["capabilities"].get("x_post", {})
        require(capability.get("daily_quota_available") is True, "durable quota capability unavailable")
        exact(capability.get("daily_quota"), QUOTA_DESCRIPTOR, "catalog quota descriptor differs")
        exact(self.health().get("operator_x_post_attempt_quota"), QUOTA_DESCRIPTOR, "Rust quota descriptor differs")
        rule, _, _ = self.mutate("/access-rules/x-post", {"name": self.run_id + "-" + suffix,
            "application_id": app["id"], "credential_id": self.credential_id,
            "operation_bundle": "x_text_post_v1", "daily_post_attempt_limit": 4}, collection="access_rules",
            result_key="access_rule", event="operator_catalog.access_rule.x_post_created", creates=True, authority_changed=True)
        require(type(rule.get("daily_post_attempt_limit")) is int and rule["daily_post_attempt_limit"] == 4,
            "actual limited rule lost quota")
        self.wait_catalog_loaded(suffix)
        return rule

    def sdk_quota(self, app, token, rule, *, generation, ordinal=None):
        phase = PHASES[len(self.completed)]
        self.current_phase = phase
        client = phase.split(":")[0]
        if ordinal is not None and ordinal <= 3:
            require(time.time_ns() // 1_000_000 < self.callback_anchor + 60000, "quota first wave missed refresh margin")
        scope = (app["principal_id"], rule["route_id"], self.policy_hash)
        request, operation = commitments(client, scope, self.credential_id, generation, self.fixture.SUBJECT)
        before = base.features.audit_cutoff(self.settled_audit())
        provider = self.provider_checkpoints[-1]
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "quota original deadline expired")
        # Only the existing command/environment selector is reused; the new
        # phase result is separately admitted and never called the old19 lane.
        code, stdout, stderr = base.run_example(client + ":first",
            base.client_environment(client + ":first", app["id"], token), min(35, remaining))
        self.clean(stdout); self.clean(stderr)
        self.completed.append(validate_sdk(phase, code, stdout, stderr, ordinal))
        self.contexts.append({"phase": phase, "scope": scope, "credential_id": self.credential_id,
            "generation": generation, "request_digest": request, "operation_digest": operation,
            "body_sha256": digest(base.profiles.post_body(client)), "ordinal": ordinal})
        self.refreshed = generation == 2 or self.refreshed
        observed = self.observe(ordinal if ordinal is not None else 4, refreshed=self.refreshed,
            expired=self.refreshed)
        if ordinal is None:
            exact(observed, provider, "quota-denied SDK contacted provider")
            events = [row for row in self.settled_audit() if row["id"] not in before]
            require(not any(row["event_type"] in {RESERVED, CLAIMED, base.RELEASE} for row in events),
                "quota-denied request reserved, claimed or released")

    def retained_restart(self, pinned, provider):
        from scripts import operator_x_post_fixture_network as network
        self.current_phase = "retained_restart"
        request = network.quota_checkpoint({"schema": "catchplate.privateXQuotaRestartRequest/v1",
            "run_id": self.run_id, "phase": "after_three", "policy_hash": self.policy_hash,
            "credential_id": self.credential_id, "application_ids": [a["id"] for a, _ in self.apps],
            "initial_access_expires_at_epoch_ms": provider["initialAccessExpiresAtEpochMs"]})
        require(network.read_quota_checkpoint() is None and network.read_quota_checkpoint(ack=True) is None,
            "quota restart checkpoint already exists")
        root = Path("/client-work")
        pending, target = root / (network.QUOTA_REQUEST + ".pending"), root / network.QUOTA_REQUEST
        network._write(pending, encoded(request), 0o600)
        os.link(pending, target, follow_symlinks=False)
        pending.unlink()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        while True:
            ack = network.read_quota_checkpoint(ack=True)
            if ack is not None:
                break
            time.sleep(min(0.1, self.timeout()))
        exact(ack, {"schema": "catchplate.privateXQuotaRestartAck/v1", "request_sha256": digest(request),
            "status": "retained_restarted"}, "quota restart acknowledgement differs")
        require(network.read_quota_checkpoint() == request, "quota restart request changed")
        self.wait_catalog_loaded("retained_restart")
        exact(authority_projection(self.warm_cas_snapshot()), authority_projection(pinned), "retained restart changed catalog authority")
        exact(self.observe(3), provider, "retained restart contacted provider or reset expiry")
        self.restart = ack

    def disconnect_account(self, rules, generation):
        pinned = self.warm_cas_snapshot()
        review = self.lifecycle_json(base.PREFIX + "/accounts/" + self.credential_id + "/disconnect-review")
        identifiers = sorted(rule["id"] for rule in rules)
        require(review.get("affected_credential_ids") == [self.credential_id]
            and review.get("affected_rule_ids") == identifiers and review.get("expected_credential_generation") == generation
            and review.get("expected_revision") == pinned["revision"]
            and review.get("expected_policy_hash") == self.policy_hash, "quota disconnect scope differs")
        exact(authority_projection(self.catalog()), authority_projection(pinned), "quota review mutated catalog")
        operation_id = str(uuid.uuid4())
        payload = {key: review[key] for key in ("credential_id", "expected_credential_generation",
            "expected_revision", "expected_policy_hash", "review_digest")}
        result = self.lifecycle_json(base.PREFIX + "/disconnect", payload={**payload, "operation_id": operation_id})
        require(set(result) == base.OPERATION_KEYS and result["operation_id"] == operation_id
            and result["kind"] == "disconnect" and result["status"] == "disconnected"
            and result["credential_id"] == self.credential_id and result["reason"] is None,
            "quota disconnect uncertain; never retry")
        exact(self.lifecycle_json(base.PREFIX + "/operations/" + operation_id), result, "quota disconnect readback differs")
        current = self.catalog()
        require(current["revision"] == pinned["revision"] + 2
            and current["policy"]["sequence"] == pinned["policy"]["sequence"] + 1
            and current["policy"]["policy_hash"] != pinned["policy"]["policy_hash"], "quota disconnect publication differs")
        for collection in base.COLLECTIONS:
            require([r["id"] for r in current[collection]] == [r["id"] for r in pinned[collection]],
                "quota disconnect changed retained inventory")
        require(self.resource(current, "credentials", self.credential_id)["status"] == "revoked"
            and all(self.resource(current, "access_rules", identifier)["status"] == "revoked" for identifier in identifiers),
            "quota disconnect did not fence account and permissions")
        expected_apps = [{**a, "active_rule_count": 0, "access_status": "unassigned"} for a in pinned["applications"]]
        exact(current["applications"], expected_apps, "quota disconnect changed retained applications")
        self.policy_hash = current["policy"]["policy_hash"]
        self.disconnects.append({"operation_id": operation_id, "credential_id": self.credential_id,
            "rule_ids": identifiers, "revision": current["revision"], "policy_hash": self.policy_hash})
        self.wait_catalog_loaded("disconnect_" + str(self.alias))
        self.cleaned = self.alias
        self.observe(4, refreshed=True, expired=True)

    def reconnect(self):
        before = self.warm_cas_snapshot()
        previous_id = self.credential_id
        self.consent_id = str(uuid.uuid4())
        status, headers, raw = self.exchange(self.control, base.PREFIX + "/start", method="POST", authenticated=True,
            payload={"name": self.run_id + "-alias", "operation_id": self.consent_id,
                "expected_revision": before["revision"], "expected_policy_hash": self.policy_hash})
        require(status == 201, "quota second consent refused; never retry")
        started = document(raw)
        target = base.consent_target(started, self.fixture.CLIENT_ID)
        require(started["operation_id"] == self.consent_id
            and started["profile_binding_digest"] == self.configuration["profile_binding_digest"], "quota alias switched client")
        cookie, nonce = base.consent_cookie(headers, started["state"])
        self.transients.extend((nonce, started["state"]))
        status, headers, raw = self.exchange(self.accounts, target)
        require(status == 302 and raw == b"", "quota second provider authorization differs")
        target, code = base.callback_target(headers, started["state"])
        self.transients.append(code)
        status, _, raw = self.exchange(self.control, target, cookie=cookie)
        require(status == 200 and b"<h1>X account connected</h1>" in raw, "quota alias callback failed; never replay")
        operation = self.lifecycle_json(base.PREFIX + "/operations/" + self.consent_id)
        require(set(operation) == base.OPERATION_KEYS and operation["operation_id"] == self.consent_id
            and operation["status"] == "connected" and operation["kind"] == "consent" and operation["reason"] is None
            and base.UUID.fullmatch(operation["credential_id"]) and operation["credential_id"] != previous_id,
            "quota alias did not genuinely adopt a new credential")
        self.credential_id = operation["credential_id"]
        current = self.catalog()
        credential = self.resource(current, "credentials", self.credential_id)
        original = self.resource(current, "credentials", previous_id)
        require(current["revision"] == before["revision"] + 3 and len(current["credentials"]) == 2
            and original == self.resource(before, "credentials", previous_id) and original["status"] == "revoked"
            and current["policy"] == before["policy"] and current["applications"] == before["applications"]
            and current["access_rules"] == before["access_rules"] and credential["status"] == "active"
            and credential["credential_generation"] == 1 and credential["provider_id"] == "x"
            and credential["provider_subject"] == self.fixture.SUBJECT and credential["oauth_client_id"] == self.fixture.CLIENT_ID
            and credential["scopes"] == base.SCOPES, "quota alias changed verified identity or retained authority")
        self.alias = 2
        self.observe(4, refreshed=True, expired=True)
        return credential

    def run(self):
        self.health()
        self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision and all(not initial[k]
            and initial["limits"][k]["retained"] == 0 for k in base.COLLECTIONS), "fresh quota fixture catalog required")
        self.initial_policy_hash = self.policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        baseline = base.features.audit_cutoff(self.settled_audit())
        first = self.configure_and_connect()
        self.first_credential_id = self.credential_id
        self.apps = []
        for name in ("a", "b"):
            app, token, _ = self.mutate("/applications", {"name": self.run_id + "-" + name,
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"},
                collection="applications", result_key="application", event="operator_catalog.application.created", creates=True, token=True)
            self.apps.append((app, token))
        rules = [self.limited_rule(app, "post-" + str(index)) for index, (app, _) in enumerate(self.apps)]
        before = self.warm_cas_snapshot()
        for ordinal, index in enumerate((0, 1, 0), 1):
            self.sdk_quota(*self.apps[index], rules[index], generation=1, ordinal=ordinal)
        exact(authority_projection(self.warm_cas_snapshot()), authority_projection(before), "quota first wave changed authority")
        self.retained_restart(before, self.provider_checkpoints[-1])
        expiry = self.provider_checkpoints[-1]["initialAccessExpiresAtEpochMs"]
        wait = (expiry + 1000 - time.time_ns() // 1_000_000) / 1000
        require(0 < wait < self.deadline - time.monotonic() - 30, "quota original budget cannot cover real expiry")
        monotonic_boundary = time.monotonic() + wait
        while time.monotonic() < monotonic_boundary or time.time_ns() // 1_000_000 < expiry + 1000:
            time.sleep(min(0.25, self.timeout()))
        self.observe(3, expired=True)
        self.sdk_quota(*self.apps[1], rules[1], generation=2, ordinal=4)
        refreshed = self.warm_cas_snapshot()
        base.require_refresh_projection(before, refreshed, self.credential_id)
        for index in (0, 1):
            self.sdk_quota(*self.apps[index], rules[index], generation=2)
        exact(authority_projection(self.warm_cas_snapshot()), authority_projection(refreshed), "quota denials changed authority")
        self.disconnect_account(rules, 2)
        alias = self.reconnect()
        alias_rule = self.limited_rule(self.apps[0][0], "alias-post")
        self.sdk_quota(*self.apps[0], alias_rule, generation=1)
        self.disconnect_account([alias_rule], 1)
        require(time.time_ns() // 1_000_000 // DAY_MS == self.day, "quota run crossed actual UTC day")
        evidence = self.verify_quota_audit(self.settled_audit(), baseline)
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
            "quota durable audit chain failed")
        self.current_files()
        result = {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realXVerified": False,
            "productionReady": False, "publicDnsVerified": False, "actualExampleEntrypoints": True,
            "actualManagedLifecycle": True, "auditChainVerified": True, "limit": 4,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "dependenciesSha256": self.args.expected_dependencies_sha256,
            "completed": self.completed, "provider": self.provider_checkpoints[-1], "restart": self.restart,
            "preCallbackEpochMs": self.callback_anchor, "credentialIds": [first["id"], alias["id"]],
            "applicationIds": [app["id"] for app, _ in self.apps], "utcDay": self.day, **evidence}
        validate_success_result(result)
        require(all(value.encode() not in encoded(result) for value in self.transients), "quota transient escaped receipt")
        return result

    def verify_quota_audit(self, events, baseline):
        # Filled by the exact production audit join below, not a private DB read.
        return verify_audit(events, baseline, self.contexts, self.arrivals,
            subject=self.fixture.SUBJECT, day=self.day, binary=self.args.expected_binary_sha256,
            mutations=self.mutations, disconnects=self.disconnects)


def ordered_audit(events):
    base.features.audit_cutoff(events)
    by_hash = {row["event_hash"]: row for row in events}
    require(len(by_hash) == len(events), "quota audit hash collision")
    children = {}
    for row in events:
        previous = row.get("prev_event_hash")
        require("prev_event_hash" in row and previous not in children, "quota audit fork or missing predecessor")
        children[previous] = row
    ordered, previous = [], None
    for _ in events:
        require(previous in children, "quota complete audit chain missing")
        row = children[previous]
        ordered.append(row)
        previous = row["event_hash"]
    require(previous not in children and len({row["id"] for row in ordered}) == len(events), "quota audit cycle")
    return ordered


def verify_audit(events, baseline, contexts, arrivals, *, subject, day, binary, mutations, disconnects):
    cutoff = base.features.audit_cutoff(events)
    require(all(cutoff.get(k) == v for k, v in baseline.items()), "quota baseline audit changed")
    ordered = ordered_audit(events)
    positions = {row["id"]: index for index, row in enumerate(ordered)}
    rows = [row for row in ordered if row["id"] not in baseline]
    counts = Counter(row["event_type"] for row in rows)
    require(set(counts) <= set(AUDIT_EXACT) | {base.LEASE, base.LEASE_REJECT, base.RELOAD}
        and all(counts[k] == v for k, v in AUDIT_EXACT.items()) and 4 <= counts[base.LEASE] <= 96
        and counts[base.LEASE_REJECT] == 3 and 3 <= counts[base.RELOAD] <= 12,
        "quota complete lifecycle/audit inventory differs")
    require([c["phase"] for c in contexts] == list(PHASES), "quota SDK context roster differs")
    starts, releases, denials, matched = {}, {}, {}, {}
    for row in rows:
        kind, event = row["event_type"], row["event"]
        if kind not in {base.START, base.RELEASE, DENIED}:
            continue
        candidates = [c for c in contexts if tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == tuple(c["scope"])
            and event.get("credential_ref") == c["credential_id"] and event.get("credential_version") == c["generation"]
            and event.get("request_digest") == c["request_digest"] and event.get("operation_digest") == c["operation_digest"]
            and event.get("body_sha256") == c["body_sha256"]]
        require(len(candidates) == 1 and type(event.get("credential_version")) is int and event.get("method") == "POST"
            and type(event.get("attempt_id")) is str and SHA256.fullmatch(event["attempt_id"])
            and event.get("flow_id") == event["attempt_id"], "quota request audit escaped actual SDK context")
        context, attempt = candidates[0], event["attempt_id"]
        target = starts if kind == base.START else releases if kind == base.RELEASE else denials
        require(attempt not in target, "quota request audit replay")
        target[attempt] = event
        matched.setdefault(attempt, {})[kind] = row
        if kind == base.START:
            require(event.get("outcome") == "release_started", "quota durable start differs")
        elif kind == base.RELEASE:
            require(context["ordinal"] is not None, "quota denied context released")
            arrival = arrivals[context["ordinal"] - 1]
            validation = event.get("response_validation", {})
            require(event.get("outcome") == "released" and type(event.get("upstream_status")) is int
                and event["upstream_status"] == 201 and validation.get("ok") is True
                and validation.get("body_bytes_preserved") is True and validation.get("mode") == "xPostJsonV1"
                and event.get("response_body_sha256") == arrival["responseBodySha256"]
                and type(event.get("response_body_bytes")) is int and event["response_body_bytes"] == arrival["responseBytes"],
                "quota release differs from actual provider bytes")
        else:
            require(context["ordinal"] is None and event.get("outcome") == "denied"
                and event.get("stage") == "operator_x_quota"
                and event.get("error") == "operator_x_post_attempt_quota_unavailable", "quota failure was not exact local denial")
    require(len(starts) == 7 and len(releases) == 4 and len(denials) == 3
        and set(releases).isdisjoint(denials) and set(starts) == set(releases) | set(denials), "quota start/terminal pairing differs")
    require(Counter((v["request_digest"], v["operation_digest"]) for v in starts.values()) ==
        Counter((c["request_digest"], c["operation_digest"]) for c in contexts), "quota SDK attempt was repeated or omitted")
    for attempt, pair in matched.items():
        terminal = pair[base.RELEASE if attempt in releases else DENIED]
        require(positions[pair[base.START]["id"]] < positions[terminal["id"]], "quota terminal precedes durable start")
    charged, reservations, bucket = validate_quota_events(rows, starts, subject=subject, day=day)
    require(set(charged) == set(releases), "quota claim and actual released attempts differ")
    quota_rows = {kind: {r["event"]["binding"]["attempt_nonce"]: r for r in rows if r["event_type"] == kind}
        for kind in (RESERVED, CLAIMED)}
    for attempt in charged:
        require(positions[matched[attempt][base.START]["id"]] < positions[quota_rows[RESERVED][attempt]["id"]]
            < positions[quota_rows[CLAIMED][attempt]["id"]] < positions[matched[attempt][base.RELEASE]["id"]],
            "quota claim was not durably ordered before response release")
    scopes = {(tuple(c["scope"]), c["credential_id"]) for c in contexts}
    issued = []
    for row in rows:
        kind, event = row["event_type"], row["event"]
        if kind == base.LEASE:
            scope = tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash"))
            require((scope, event.get("credential_id")) in scopes, "quota lease issued to unrelated scope")
            base.validate_issued_lease(event, scope, event["credential_id"], binary)
            issued.append(row)
        elif kind == base.LEASE_REJECT:
            require(event.get("outcome") == "rejected" and type(event.get("status_code")) is int
                and event["status_code"] == 429 and event.get("reason") == "X posting-attempt quota exhausted"
                and event.get("purpose") == "dispatchSecret" and event.get("data_plane_binary_digest") == binary
                and (tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")), event.get("credential_id")) in scopes
                and event.get("credential_ids") == [] and type(event.get("credential_count")) is int and event["credential_count"] == 0,
                "quota signed rejection differs")
        elif kind == base.CONNECT:
            require(event.get("target") == "api.x.com:443" and event.get("method") == "CONNECT"
                and event.get("outcome") == "established" and (event.get("principal_id"), event.get("policy_hash"))
                in {(c["scope"][0], c["scope"][2]) for c in contexts}, "quota tunnel scope differs")
    for attempt in charged:
        binding = quota_rows[CLAIMED][attempt]["event"]["binding"]
        require(any(r["event"].get("purpose") == "dispatchSecret"
            and all(r["event"].get(k) == binding[b] for k, b in (("principal_id", "principal_id"), ("route_id", "route_id"),
                ("credential_id", "credential_id"), ("policy_hash", "policy_hash"),
                ("expected_credential_version", "credential_version"), ("expected_metadata_sha256", "credential_metadata_digest")))
            and positions[quota_rows[RESERVED][attempt]["id"]] < positions[r["id"]] < positions[quota_rows[CLAIMED][attempt]["id"]]
            for r in issued), "quota claim missing exact encrypted lease audit")
    exact(sorted((r["event_type"], r["event"].get("resource_id"), r["event"].get("policy_hash")) for r in rows
        if r["event_type"] in {"operator_catalog.application.created", "operator_catalog.access_rule.x_post_created"}),
        sorted(mutations), "quota mutation audits differ from actual HTTP receipts")
    for item in disconnects:
        fences = [r for r in rows if r["event_type"] == base.LIFECYCLE + "disconnect_fenced"
            and r["event"].get("operation_id") == item["operation_id"]]
        completed = [r for r in rows if r["event_type"] == base.LIFECYCLE + "disconnected"
            and r["event"].get("operation_id") == item["operation_id"]]
        require(len(fences) == len(completed) == 1 and fences[0]["event"].get("credential_ids") == [item["credential_id"]]
            and fences[0]["event"].get("revoked_rule_ids") == item["rule_ids"]
            and fences[0]["event"].get("policy_hash") == item["policy_hash"]
            and completed[0]["event"].get("revision") == item["revision"], "quota actual disconnect audit differs")
        require(all(positions[r["id"]] < positions[fences[0]["id"]] for r in issued
            if r["event"]["credential_id"] == item["credential_id"]), "quota lease issued after local disconnect fence")
    return {"attemptIds": sorted(starts), "chargedAttemptIds": charged, "deniedAttemptIds": sorted(denials),
        "reservationIds": reservations, "bucketKey": bucket, "namedAuditInventory": dict(sorted(counts.items()))}


def validate_success_result(value):
    fields = {"schema", "ok", "syntheticOnly", "realXVerified", "productionReady", "publicDnsVerified",
        "actualExampleEntrypoints", "actualManagedLifecycle", "auditChainVerified", "limit", "dataPlaneBinaryDigest",
        "goExampleSha256", "dependenciesSha256", "completed", "provider", "restart", "preCallbackEpochMs",
        "credentialIds", "applicationIds", "utcDay", "attemptIds", "chargedAttemptIds", "deniedAttemptIds",
        "reservationIds", "bucketKey", "namedAuditInventory"}
    require(type(value) is dict and set(value) == fields and value["schema"] == SCHEMA
        and all(value[k] is True for k in ("ok", "syntheticOnly", "actualExampleEntrypoints", "actualManagedLifecycle", "auditChainVerified"))
        and all(value[k] is False for k in ("realXVerified", "productionReady", "publicDnsVerified"))
        and type(value["limit"]) is int and value["limit"] == 4 and type(value["utcDay"]) is int and value["utcDay"] > 0,
        "quota terminal boundary differs")
    exact(value["completed"], [{"phase": phase, "exitCode": 0 if index < 4 else 2, "confirmed": index < 4}
        for index, phase in enumerate(PHASES)], "quota seven SDK outcomes differ")
    require(type(value["dataPlaneBinaryDigest"]) is str and SHA256.fullmatch(value["dataPlaneBinaryDigest"])
        and all(type(value[k]) is str and base.HEX.fullmatch(value[k]) for k in ("goExampleSha256", "dependenciesSha256")),
        "quota pinned executable/dependency proof missing")
    for key, count, pattern in (("credentialIds", 2, base.UUID), ("applicationIds", 2, base.UUID),
            ("reservationIds", 4, base.UUID), ("attemptIds", 7, SHA256), ("chargedAttemptIds", 4, SHA256),
            ("deniedAttemptIds", 3, SHA256)):
        require(type(value[key]) is list and len(value[key]) == len(set(value[key])) == count
            and all(type(v) is str and pattern.fullmatch(v) for v in value[key]), "quota unique identity roster differs")
    require(set(value["chargedAttemptIds"]).isdisjoint(value["deniedAttemptIds"])
        and set(value["attemptIds"]) == set(value["chargedAttemptIds"]) | set(value["deniedAttemptIds"]),
        "quota claimed/denied attempt partition differs")
    from scripts import operator_x_post_fixture as fixture
    validate_provider(value["provider"], posts=4, consents=2, refreshed=True, cleaned=2,
        anchor=value["preCallbackEpochMs"], expired=True)
    require(value["bucketKey"] == digest({"provider": "x", "subject": fixture.SUBJECT,
        "operation": "tweets.write", "utc_day": value["utcDay"]}), "quota account-day key differs")
    ack = value["restart"]
    require(type(ack) is dict and set(ack) == {"schema", "request_sha256", "status"}
        and ack["schema"] == "catchplate.privateXQuotaRestartAck/v1" and ack["status"] == "retained_restarted"
        and type(ack["request_sha256"]) is str and SHA256.fullmatch(ack["request_sha256"]), "quota actual retained restart ACK missing")
    counts = value["namedAuditInventory"]
    require(type(counts) is dict and all(type(v) is int and 0 <= v <= 1000 for v in counts.values())
        and set(counts) <= set(AUDIT_EXACT) | {base.LEASE, base.LEASE_REJECT, base.RELOAD}
        and all(counts.get(k) == v for k, v in AUDIT_EXACT.items()) and 4 <= counts.get(base.LEASE, 0) <= 96
        and counts.get(base.LEASE_REJECT) == 3 and 3 <= counts.get(base.RELOAD, 0) <= 12,
        "quota durable terminal inventory differs")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256",
            "expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file",
            "run-claim-file", "dependencies-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--expected-initial-revision", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    check = None
    def expired(*_):
        raise CheckFailure("quota checker original deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "quota checker original bounds differ")
        signal.alarm(180)
        base.claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = XQuotaCheck(args)
        result = check.run()
        check.clean(encoded(result))
    except Exception as error:
        from scripts.run_operator_x_examples_fixture import failure_site
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "productionReady": False,
            "error": "managed X quota acceptance failed; no retry authorized", "failureSite": failure_site(error, Path("/app")),
            "phase": check.current_phase if check is not None and check.current_phase in (*PHASES, "retained_restart") else None,
            "completed": check.completed if check is not None else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
