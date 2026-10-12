#!/usr/bin/env python3
"""One fresh GitHub App -> real lease/Rust -> three ordinary SDK acceptance.

No stack launch, dependencies, clock patching, cache clearing or command retry.
Provisioning uses the real authenticated catalog API and HTTPS protocol.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
from urllib.parse import parse_qsl, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_github_examples as stock
from scripts import operator_github_app_examples_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, PREFIX, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, require, token_file
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, digest
from scripts.check_operator_github import CONNECT_DENIED, KEEP_ALIVE
from scripts.check_operator_key_replacement import authority_projection

SCHEMA = "serverware.privateGithubAppExamplesCheck/v2"
REPLACED = "operator_catalog.credential.github_app_key_replaced"
LEASE_CAP_MS, WAIT_SECONDS = 5000, 5.25
READ_PHASES = {"read_initial", "read_renewed", "read_rotated"}
PHASES = {"initial", "connection", "grant", "read_initial", "wrong_app", "wrong_repo",
          "expiry_wait", "read_renewed", "replace_failed", "replace", "lease_wait",
          "read_rotated", "revoke", "revoked", "audit"}


def read_key(path):
    require(path in {Path("/client-secrets/github-app.pem"), Path("/client-secrets/github-app-replacement.pem")},
        "fixed synthetic App key required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o400 and 1 <= info.st_size <= 16384,
            "synthetic App key file refused")
        raw = os.read(fd, 16385)
        require(len(raw) == info.st_size, "synthetic App key changed")
        return raw.decode("ascii")
    finally:
        os.close(fd)


def validate_observation(value):
    require(type(value) is dict and set(value) == {"schema", "syntheticOnly", "total", "auth", "attempts", "mints"}
        and value["schema"] == fixture.SCHEMA and value["syntheticOnly"] is True
        and type(value["total"]) is int and 0 <= value["total"] <= fixture.MAX_ARRIVALS
        and all(type(value[k]) is list for k in ("auth", "attempts", "mints"))
        and value["total"] == len(value["auth"]) + len(value["attempts"])
        and len(value["auth"]) <= 10 and len(value["attempts"]) <= 18 and len(value["mints"]) <= 3,
        "App provider observations differ")
    all_rows = value["auth"] + value["attempts"]
    require(sorted(row.get("ordinal") for row in all_rows) == list(range(1, value["total"] + 1))
        and all(row.get("accepted") is True for row in all_rows), "provider refused or lost an arrival")
    for index, row in enumerate(value["auth"]):
        rejected = index == 3
        cycle = 1 if index < 4 else 2 if index < 7 else 3
        step = 0 if rejected else index if index < 3 else (index - 4) % 3
        require(set(row) == {"ordinal", "accepted", "kind", "cycle", "method", "status", "jwtVerified",
                "signingKey", "bindingMatches"}
            and row["kind"] == ("installation", "mint", "repositories")[step]
            and type(row["cycle"]) is int and row["cycle"] == cycle
            and row["method"] == ("POST" if step == 1 else "GET")
            and type(row["status"]) is int and row["status"] == (201 if step == 1 else 200)
            and row["jwtVerified"] is (step < 2) and row["bindingMatches"] is (not rejected)
            and row["signingKey"] == ("B" if rejected or cycle == 3 else "A"), "App provisioning oracle differs")
    for index, mint in enumerate(value["mints"]):
        require(type(mint) is dict and set(mint) == {"ordinal", "issuedAt", "expiresAt", "selection", "permissions", "signingKey"}
            and type(mint["ordinal"]) is int and mint["ordinal"] == index + 1
            and type(mint["issuedAt"]) is int and type(mint["expiresAt"]) is int
            and mint["issuedAt"] > 0 and mint["expiresAt"] - mint["issuedAt"] == (fixture.TOKEN_SECONDS if index == 0 else 3600)
            and mint["selection"] == ("name" if index == 0 else "id")
            and mint["permissions"] == fixture.PERMISSIONS
            and mint["signingKey"] == ("B" if index == 2 else "A"), "scoped mint observation differs")
    require(len(value["mints"]) == sum(row["kind"] == "mint" for row in value["auth"]),
        "mint observation has no accepted provisioning request")
    if len(value["mints"]) >= 2:
        require(value["mints"][1]["issuedAt"] > value["mints"][0]["expiresAt"], "original token expiry was not crossed")
    if len(value["mints"]) == 3:
        require(value["mints"][2]["issuedAt"] >= value["mints"][1]["issuedAt"], "replacement mint preceded renewal")
    for index, row in enumerate(value["attempts"]):
        require(set(row) == stock.ROW_KEYS | {"cycle", "signingKey"} and type(row["cycle"]) is int
            and row["cycle"] == index // 6 + 1
            and row["signingKey"] == ("B" if index >= 12 else "A"), "App resource cycle differs")
        original = {k: v for k, v in row.items() if k not in {"cycle", "signingKey"}}
        # PAT's exact raw request/response grammar, not its credential source.
        original["ordinal"] = index % 6 + 1
        stock.validate_row(original, index % 6 + 1, fixture.examples.CLIENTS[(index % 6) // 2], index % 2 + 1)
    return value


def canonical_digests(row, scope, credential_id, peer, generation):
    """Independent v3 wire oracle; the retained PAT helper fixes generation one."""
    require(type(generation) is int and generation in {1, 2}, "App generation refused")
    parts = urlsplit(fixture.examples.ORIGIN + row["target"])
    canonical = {"v": 3, "principal": scope[0], "client_ip": peer, "route_id": scope[1],
        "credential_ref": credential_id, "credential_version": str(generation), "policy_hash": scope[2],
        "request": {"method": "GET", "scheme": "https", "authority": "api.github.com", "path": parts.path,
            "query": [list(pair) for pair in parse_qsl(parts.query, keep_blank_values=True,
                encoding="utf-8", errors="strict")], "query_wire": parts.query, "query_mode": "githubRestV1",
            "headers": {"host": "api.github.com", **row["semanticHeaders"]},
            "body_sha256": digest(b""), "discard_headers": ["accept-encoding"]},
        "operation": {"operation": "github.issues.read"}}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return digest(encode(canonical)), digest(encode({k: v for k, v in canonical.items() if k not in {"v", "client_ip"}}))


def match_pairs(rows, wire, scope, credential_id):
    """Repeated canonical requests still require distinct complete attempt IDs."""
    expected = Counter((*w.get("scope", scope), w.get("generation", 1), w["requestDigest"],
        w["operationDigest"], w["responseBodySha256"], w["responseBodyBytes"]) for w in wire)
    pairs = {}
    for row in rows:
        if row["event_type"] not in {START, RELEASE}:
            continue
        event, kind = row["event"], row["event_type"]
        attempt = event.get("attempt_id")
        require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt
            and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
            and event["credential_version"] in {1, 2} and event.get("method") == "GET"
            and event.get("body_sha256") == digest(b"")
            and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash", "credential_version",
                "request_digest", "operation_digest")) in {key[:-2] for key in expected},
            "App audit authority differs")
        pair = pairs.setdefault(attempt, {})
        slot = "start" if kind == START else "release"
        require(slot not in pair, "App attempt has duplicate terminals or starts")
        pair[slot] = row
    require(len(pairs) <= len(wire), "extra App request attempt")
    complete = []
    for attempt, pair in pairs.items():
        if set(pair) != {"start", "release"}:
            continue
        start, release = pair["start"]["event"], pair["release"]["event"]
        key = tuple(release.get(k) for k in ("principal_id", "route_id", "policy_hash", "credential_version",
            "request_digest", "operation_digest", "response_body_sha256", "response_body_bytes"))
        require(start.get("outcome") == "release_started" and release.get("outcome") == "released"
            and tuple(start.get(k) for k in ("principal_id", "route_id", "policy_hash", "credential_version",
                "request_digest", "operation_digest")) == key[:-2]
            and release.get("upstream_status") == 200 and expected[key] > 0,
            "App request/response commitments differ")
        validation = release.get("response_validation", {})
        require(validation.get("ok") is True and validation.get("body_bytes_preserved") is True
            and validation.get("mode") == "bufferedJsonOrEmpty204V2", "App response guard differs")
        expected[key] -= 1
        complete.append({"attemptId": attempt, "startId": pair["start"]["id"], "releaseId": pair["release"]["id"]})
    return complete if len(complete) == len(wire) and not any(expected.values()) else None


def validate_revoked_credential(before, after, *, generation=1, active_rules=1):
    """Only the sole grant's derived count changes; custody stays identical."""
    require(type(before) is dict and type(after) is dict
        and type(before.get("active_rule_count")) is int and before["active_rule_count"] == active_rules
        and type(after.get("active_rule_count")) is int and after["active_rule_count"] == 0
        and type(before.get("credential_generation")) is int and before["credential_generation"] == generation
        and type(after.get("credential_generation")) is int and after["credential_generation"] == generation,
        "App credential generation or revoked grant count differs")
    expected = {**before, "active_rule_count": 0}
    # JSON equality also distinguishes bool/int/float substitutions, retaining
    # all current and future public fields rather than a selected subset.
    require(json.dumps(after, sort_keys=True) == json.dumps(expected, sort_keys=True),
        "App credential changed during rule revocation")


def validate_replacement(before, after, credential_id):
    """Permit only the documented revision, credential version/generation/time."""
    old = [row for row in before["credentials"] if row["id"] == credential_id]
    new = [row for row in after["credentials"] if row["id"] == credential_id]
    require(len(old) == len(new) == len(before["credentials"]) == len(after["credentials"]) == 1,
        "replacement credential roster differs")
    old, new = old[0], new[0]
    require(type(old.get("credential_generation")) is int and old["credential_generation"] == 1
        and type(old.get("version")) is int and old["version"] == 1
        and old.get("active_rule_count") == 2 and type(new.get("key_replaced_at")) is str
        and len(new["key_replaced_at"]) <= 64, "replacement generation or timestamp differs")
    stamp = datetime.fromisoformat(new["key_replaced_at"].replace("Z", "+00:00"))
    require(stamp.tzinfo is not None and stamp.timestamp() > 0, "replacement timestamp invalid")
    expected_credential = {**old, "credential_generation": 2, "version": 2,
        "key_replaced_at": new["key_replaced_at"]}
    expected = {**authority_projection(before), "revision": before["revision"] + 1,
        "credentials": [expected_credential]}
    require(json.dumps(authority_projection(after), sort_keys=True) == json.dumps(expected, sort_keys=True),
        "replacement changed policy, assignments, binding or other authority")
    return new


class AppExamplesCheck(stock.ExamplesCheck):
    def __init__(self, args):
        self.app_pem = self.replacement_pem = None
        super().__init__(args)
        self.current_phase, self.pairs = "initial", []
        self.app_pem = read_key(args.app_key_file)
        self.replacement_pem = read_key(args.replacement_key_file)
        require(self.app_pem != self.replacement_pem, "distinct synthetic signing keys required")
        self.reloads, self.lease_scopes = [], set()

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        sensitive = list(fixture.TOKENS)
        for pem in (self.app_pem, getattr(self, "replacement_pem", None)):
            if pem:
                sensitive += [pem, *[line for line in pem.splitlines() if not line.startswith("-----")]]
        require(all(value.encode("ascii") not in content for value in sensitive), "App material escaped")

    def observe(self):
        status, value = self.json_request(self.github, "/_fixture/observations", context=self.upstream_ca)
        require(status == 200, "App provider observation failed")
        return validate_observation(value)

    def count(self):
        return len(self.observe()["attempts"])

    def example(self, client, phase, application, token):
        self.current_client, self.current_phase = client, phase
        code, stdout, stderr = stock.run_example(client, stock.client_environment(client, application["id"], token,
            wrong_repo=phase == "wrong_repo"), min(40, self.deadline - time.monotonic()))
        self.clean(stdout); self.clean(stderr)
        if phase in READ_PHASES:
            require(code == 0 and not stderr and json.loads(stdout) == stock.expected_output(client), "App SDK read failed")
        else:
            require(code == 1, "App SDK denial did not fail closed")
        self.completed.append({"client": client, "phase": phase, "exitCode": code})

    def policy_checkpoint(self, previous, label, assigned, routes):
        self.wait_catalog_loaded(label)
        current = self.warm_cas_snapshot()
        self.reloads.append((previous, self.policy_hash, current["policy"]["sequence"], routes))
        for app, rule, _ in assigned:
            if self.resource(current, "access_rules", rule["id"])["status"] == "active":
                self.lease_scopes.add((app["principal_id"], rule["route_id"], self.policy_hash))
        return current

    def failed_replacement(self, credential_id):
        self.current_phase = "replace_failed"
        before, observed = self.warm_cas_snapshot(), self.observe()
        baseline = features.audit_cutoff(self.audit())
        status, result = self.json_request(self.control, PREFIX + "/credentials/github-app/replace-key",
            context=self.control_ca, method="POST", authenticated=True, payload={
                "expected_revision": before["revision"], "expected_policy_hash": self.policy_hash,
                "id": credential_id, "expected_credential_generation": 1, "private_key_pem": self.replacement_pem})
        require(status == 503 and result == {"detail":
            "GitHub App verification failed; check app, installation and repository permissions"},
            "failed candidate did not return the fixed verification refusal")
        require(authority_projection(self.warm_cas_snapshot()) == authority_projection(before),
            "failed replacement changed saved authority")
        after = self.observe()
        require(len(observed["auth"]) == 3 and len(after["auth"]) == 4
            and after["auth"][:3] == observed["auth"] and after["mints"] == observed["mints"]
            and after["attempts"] == observed["attempts"] == [], "failed candidate minted or dispatched")
        events = self.audit(); cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for k, v in baseline.items())
            and not any(row["event_type"].startswith("operator_catalog.") for row in events if row["id"] not in baseline),
            "failed replacement mutated durable catalog audit")

    def replace_and_wait(self, credential_id):
        self.current_phase = "replace"
        before = self.warm_cas_snapshot()
        _, issued, receipt = self.submit_mutation(before, "/credentials/github-app/replace-key",
            {"id": credential_id, "expected_credential_generation": 1, "private_key_pem": self.replacement_pem},
            result_key="credential")
        committed = time.monotonic()
        details = receipt.get("key_replacement", {})
        require(issued is None and set(receipt) == {"credential", "revision", "policy", "key_replacement"}
            and set(details) == {"previous_credential_generation", "credential_generation", "cache_invalidation", "in_flight_requests"}
            and type(details["previous_credential_generation"]) is int and details["previous_credential_generation"] == 1
            and type(details["credential_generation"]) is int and details["credential_generation"] == 2
            and details["cache_invalidation"] in {"local_completed", "local_unconfirmed"}
            and details["in_flight_requests"] == "not_recalled", "replacement receipt differs")
        after = self.warm_cas_snapshot()
        validate_replacement(before, after, credential_id)
        self.finalize_mutation(receipt, after, collection="credentials", result_key="credential", event=REPLACED)
        self.current_phase = "lease_wait"
        # This only exceeds precommit lease lifetime; it is not instant recall.
        while time.monotonic() - committed < WAIT_SECONDS:
            time.sleep(min(0.25, self.timeout(), max(0.0, WAIT_SECONDS - (time.monotonic() - committed))))
        waited = time.monotonic() - committed
        require(waited >= WAIT_SECONDS, "post-commit wait shortened")
        self.wait_evidence = {"sourceLeaseTtlUpperBoundMs": LEASE_CAP_MS,
            "minimumPostCommitWaitMs": 5250, "actualPostCommitWaitMonotonicNs": int(waited * 1_000_000_000),
            "remoteInvalidationAcknowledged": False, "inFlightRequestsRecalled": False}
        self.unchanged(after)
        return after

    def wait_pairs(self, baseline, wire, scope, credential_id):
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in baseline.items()), "App audit history changed")
            rows = [row for row in events if row["id"] not in baseline]
            require(not any(row["event_type"] in {DENIED, BLOCK, CONNECT_DENIED} for row in rows), "successful App job was denied")
            pairs = match_pairs(rows, wire, scope, credential_id)
            if pairs is not None and self.audit_drained():
                self.pairs.extend(pairs)
                return
            time.sleep(min(0.1, self.timeout()))

    def negative(self, client, phase, application, token):
        baseline, observed = features.audit_cutoff(self.audit()), self.observe()
        self.example(client, phase, application, token)
        expected = DENIED if phase == "wrong_repo" else CONNECT_DENIED
        while True:
            events = self.audit(); cutoff = features.audit_cutoff(events)
            require(all(cutoff.get(k) == v for k, v in baseline.items()) and self.observe() == observed,
                "denied App job changed provider or audit history")
            rows = [row for row in events if row["id"] not in baseline]
            require(not any(row["event_type"] in {START, RELEASE, BLOCK}
                or row["event_type"] == LEASE and row["event"].get("purpose") == "dispatchSecret" for row in rows),
                "denied App job acquired a dispatch credential")
            denied = [row for row in rows if row["event_type"] in {DENIED, CONNECT_DENIED}]
            require(len(denied) <= 1 and all(row["event_type"] == expected and row["event"].get("outcome") == "denied"
                and row["event"].get("method") == ("GET" if phase == "wrong_repo" else "CONNECT") for row in denied),
                "App denial count or kind differs")
            if expected == CONNECT_DENIED:
                require(all(row["event"].get("target") == "api.github.com:443"
                    and row["event"].get("principal_id") is None for row in denied), "App denied CONNECT target differs")
            if denied and self.audit_drained():
                return
            time.sleep(min(0.1, self.timeout()))

    def wait_original_expiry(self):
        self.current_phase = "expiry_wait"
        first = self.observe()
        require(len(first["mints"]) == 1 and len(first["attempts"]) == 6, "unexpected early refresh")
        while time.time() <= first["mints"][0]["expiresAt"] + 1:
            require(self.observe() == first, "provider changed during idle expiry wait")
            time.sleep(min(1, self.timeout()))

    def audit_result(self, baseline, scope, credential, revoked_hash):
        events = self.audit(); cutoff = features.audit_cutoff(events)
        require(all(cutoff.get(k) == v for k, v in baseline.items()), "final App audit prefix differs")
        rows = [row for row in events if row["id"] not in baseline]
        counts = Counter(row["event_type"] for row in rows)
        exact = Counter(kind for kind, _, _ in self.mutations)
        exact.update({START: 18, RELEASE: 18, DENIED: 3, CONNECT_DENIED: 6, RELOAD: 4})
        require(set(counts) <= set(exact) | {CONNECT, KEEP_ALIVE, LEASE}
            and all(counts[k] == v for k, v in exact.items()) and counts[LEASE] <= 64
            and counts[CONNECT] + counts[KEEP_ALIVE] == 21 and counts[KEEP_ALIVE] <= 9,
            "final App audit inventory differs")
        pairs = match_pairs(rows, self.wire, scope, credential["id"])
        require(pairs is not None and {p["attemptId"] for p in pairs} == {p["attemptId"] for p in self.pairs}
            and len(self.pairs) == 18, "App attempts were lost or reused")
        scopes = {tuple(w["scope"]) for w in self.wire}
        require(len(scopes) == 2, "two distinct assigned scopes required")
        leases, dispatch_scopes, reloads, replacements = [], set(), Counter(), []
        for row in rows:
            event, kind = row["event"], row["event_type"]
            if kind == LEASE:
                require(event.get("outcome") == "issued" and event.get("status_code") == 200
                    and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) in self.lease_scopes
                    and event.get("credential_id") == credential["id"]
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "App lease authority differs")
                issued, expiry = event.get("issued_at_epoch_ms"), event.get("expires_at_epoch_ms")
                require(type(issued) is int and type(expiry) is int and 0 < expiry - issued <= LEASE_CAP_MS,
                    "issued lease exceeds replacement wait basis")
                if event["purpose"] == "dispatchSecret":
                    actual_scope = tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash"))
                    generation = event.get("expected_credential_version")
                    require(actual_scope in scopes and type(generation) is int and generation in {1, 2},
                        "App dispatch scope or generation differs")
                    dispatch_scopes.add((actual_scope, generation))
                    leases.append(row["id"])
            elif kind in {CONNECT, KEEP_ALIVE}:
                require(event.get("target") == "api.github.com:443"
                    and (event.get("principal_id"), event.get("policy_hash")) in {(s[0], s[2]) for s in scopes},
                    "App CONNECT binding differs")
            elif kind == RELOAD:
                transition = tuple(event.get(k) for k in ("previous_policy_hash", "policy_hash", "policy_sequence", "routes"))
                require(type(event.get("policy_sequence")) is int and type(event.get("routes")) is int
                    and transition in self.reloads, "App policy reload differs")
                reloads[transition] += 1
            elif kind == REPLACED:
                require(event.get("resource_id") == credential["id"]
                    and type(event.get("previous_credential_generation")) is int and event["previous_credential_generation"] == 1
                    and type(event.get("credential_generation")) is int and event["credential_generation"] == 2
                    and event.get("policy_hash") in {s[2] for s in scopes}, "App replacement audit differs")
                replacements.append(row["id"])
        require(dispatch_scopes == {(s, g) for s in scopes for g in (1, 2)}
            and reloads == Counter(self.reloads) and len(replacements) == 1
            and self.reloads[-1][1] == revoked_hash and self.reloads[-1][3] == 1
            and Counter(self.mutations) == Counter((r["event_type"], r["event"].get("resource_id"),
                r["event"].get("policy_hash")) for r in rows if r["event_type"].startswith("operator_catalog.")),
            "App mutation, reload or dispatch evidence missing")
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True and self.audit_drained(), "App audit chain incomplete")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(p["attemptId"] for p in pairs),
            "dispatchLeaseIds": leases, "replacementAuditEventIds": replacements}

    def run(self):
        self.health(); self.admin_token = token_file(self.args.admin_token_file)
        initial = self.catalog()
        require(initial["revision"] == self.args.expected_initial_revision
            and all(not initial[key] and initial["limits"][key]["retained"] == 0 for key in COLLECTIONS)
            and self.observe()["total"] == 0 and initial.get("capabilities", {}).get("github_app", {}).get("connection_type") == "github_app_v1",
            "fresh App-capable catalog required")
        self.policy_hash = self.initial_policy_hash = initial["policy"]["policy_hash"]
        self.wait_catalog_loaded("initial")
        while not self.audit_drained():
            time.sleep(min(0.1, self.timeout()))
        baseline = features.audit_cutoff(self.audit())
        self.current_phase = "connection"
        credential, _, _ = self.mutate("/credentials/github-app", {"name": self.run_id + "-github-app",
            "app_id": str(fixture.APP_ID), "installation_id": str(fixture.INSTALLATION_ID), "private_key_pem": self.app_pem,
            "repository": {"owner": fixture.examples.OWNER, "name": fixture.examples.REPO}, "issues_permission": "read"},
            collection="credentials", result_key="credential", event="operator_catalog.credential.github_app_created", creates=True)
        require(credential.get("connection_type") == "github_app_v1" and credential.get("credential_generation") == 1
            and credential.get("github_app", {}).get("repository_id") == str(fixture.REPOSITORY_ID), "verified App binding differs")
        self.current_phase = "grant"
        apps = [self.mutate("/applications", {"name": self.run_id + "-" + label, "token_lifetime_seconds": 3600,
            "proxy_authentication": "basic_and_bearer_v1"}, collection="applications", result_key="application",
            event="operator_catalog.application.created", creates=True, token=True)[:2]
            for label in ("assigned-first", "assigned-second", "unassigned")]
        assigned = []
        for index, (application, token) in enumerate(apps[:2]):
            previous = self.policy_hash
            rule, _, _ = self.mutate("/access-rules/github", {"name": self.run_id + "-read-" + str(index),
                "application_id": application["id"], "credential_id": credential["id"],
                "operation_bundle": "github_issues_read_v1", "repository": {
                    "owner": fixture.examples.OWNER, "name": fixture.examples.REPO}},
                collection="access_rules", result_key="access_rule", event="operator_catalog.access_rule.github_created",
                creates=True, authority_changed=True)
            assigned.append((application, rule, token))
            self.policy_checkpoint(previous, "assigned-" + str(index), assigned, index + 1)
        pins = self.warm_cas_snapshot()
        require([len(pins[k]) for k in COLLECTIONS] == [1, 3, 2], "exact shared-credential resource budget required")
        self.failed_replacement(credential["id"])
        for cycle, phase in ((1, "read_initial"), (2, "read_renewed"), (3, "read_rotated")):
            if cycle == 2:
                for client in fixture.examples.CLIENTS:
                    self.negative(client, "wrong_app", *apps[2]); self.negative(client, "wrong_repo", *apps[0])
                self.wait_original_expiry()
            elif cycle == 3:
                pins = self.replace_and_wait(credential["id"])
            generation = 2 if cycle == 3 else 1
            for client in fixture.examples.CLIENTS:
                application, rule, token = assigned[1 if client == "go" else 0]
                scope = (application["principal_id"], rule["route_id"], self.policy_hash)
                self.unchanged(pins)
                before = features.audit_cutoff(self.audit())
                first_index = len(self.wire)
                self.example(client, phase, application, token)
                observed = self.observe()
                require(len(observed["attempts"]) == first_index + 2 and len(observed["mints"]) == cycle, "SDK count or renewal differs")
                current = []
                for row in observed["attempts"][first_index:]:
                    request, operation = canonical_digests(row, scope, credential["id"], self.proxy.address, generation)
                    current.append({"requestDigest": request, "operationDigest": operation,
                        "responseBodySha256": row["responseBodySha256"], "responseBodyBytes": row["responseBodyBytes"],
                        "scope": scope, "generation": generation})
                self.wire.extend(current)
                self.wait_pairs(before, current, scope, credential["id"])
        self.unchanged(pins)
        self.current_phase = "revoke"
        for index, (_, rule, _) in enumerate(assigned):
            previous = self.policy_hash
            self.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule.revoked", authority_changed=True)
            self.policy_checkpoint(previous, "revoked-" + str(index), assigned, 1)
        revoked = self.warm_cas_snapshot()
        require(all(self.resource(revoked, "access_rules", rule["id"])["status"] == "revoked" for _, rule, _ in assigned),
            "App rule revocation did not persist")
        validate_revoked_credential(self.resource(pins, "credentials", credential["id"]),
            self.resource(revoked, "credentials", credential["id"]), generation=2, active_rules=2)
        for client in fixture.examples.CLIENTS:
            application, _, token = assigned[1 if client == "go" else 0]
            self.negative(client, "revoked", application, token)
        self.current_phase = "audit"
        evidence = self.audit_result(baseline, None, credential, self.policy_hash)
        observed = self.observe()
        require(observed["total"] == 28 and len(observed["auth"]) == 10 and len(observed["attempts"]) == 18,
            "final App provider counts differ")
        return {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realGithubVerified": False, "productionReady": False,
            "actualExampleEntrypoints": True, "providerAttempts": 18, "provisioningAttempts": 10, "mints": observed["mints"],
            "releases": 18, "deniedBeforeDispatch": 9, "initialCredentialGeneration": 1, "replacementCredentialGeneration": 2,
            "failedReplacementPreserved": True, "assignmentsPreserved": True, "leaseExpiryWait": self.wait_evidence,
            "assignedApplicationIds": [app["id"] for app, _, _ in assigned], "assignedRuleIds": [rule["id"] for _, rule, _ in assigned],
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "exampleSourceSha256": self.example_sources, "completed": self.completed,
            "pythonTrust": "client-only-union-not-independent-roots", **evidence}


def validate_success_result(value):
    keys = {"schema", "ok", "syntheticOnly", "realGithubVerified", "productionReady", "actualExampleEntrypoints",
        "providerAttempts", "provisioningAttempts", "mints", "releases", "deniedBeforeDispatch",
        "initialCredentialGeneration", "replacementCredentialGeneration", "failedReplacementPreserved",
        "assignmentsPreserved", "leaseExpiryWait", "assignedApplicationIds", "assignedRuleIds",
        "dataPlaneBinaryDigest", "goExampleSha256", "exampleSourceSha256", "completed", "pythonTrust",
        "namedAuditInventory", "auditAttemptIds", "dispatchLeaseIds", "replacementAuditEventIds"}
    require(type(value) is dict and set(value) == keys and value.get("schema") == SCHEMA and value.get("ok") is True
        and value.get("syntheticOnly") is True and value.get("actualExampleEntrypoints") is True
        and value.get("realGithubVerified") is False and value.get("productionReady") is False
        and value.get("failedReplacementPreserved") is True and value.get("assignmentsPreserved") is True
        and type(value.get("initialCredentialGeneration")) is int and value["initialCredentialGeneration"] == 1
        and type(value.get("replacementCredentialGeneration")) is int and value["replacementCredentialGeneration"] == 2
        and [value.get(k) for k in ("providerAttempts", "provisioningAttempts", "releases", "deniedBeforeDispatch")] == [18, 10, 18, 9]
        and len(value.get("auditAttemptIds", [])) == len(set(value.get("auditAttemptIds", []))) == 18
        and len(value.get("dispatchLeaseIds", [])) >= 4 and len(value.get("replacementAuditEventIds", [])) == 1,
        "App checker result incomplete")
    require(SHA256.fullmatch(value["dataPlaneBinaryDigest"]) and len(value["goExampleSha256"]) == 64
        and set(value["exampleSourceSha256"]) == set(stock.SOURCE_FILES)
        and value["pythonTrust"] == "client-only-union-not-independent-roots"
        and all(type(v) is int and v > 0 for v in value["namedAuditInventory"].values()), "App result identities differ")
    expected = [{"client": client, "phase": phase, "exitCode": 0} for client in fixture.examples.CLIENTS for phase in ("read_initial",)]
    expected += [{"client": client, "phase": phase, "exitCode": 1} for client in fixture.examples.CLIENTS for phase in ("wrong_app", "wrong_repo")]
    expected += [{"client": client, "phase": "read_renewed", "exitCode": 0} for client in fixture.examples.CLIENTS]
    expected += [{"client": client, "phase": "read_rotated", "exitCode": 0} for client in fixture.examples.CLIENTS]
    expected += [{"client": client, "phase": "revoked", "exitCode": 1} for client in fixture.examples.CLIENTS]
    require(value.get("completed") == expected and len(value.get("mints", [])) == 3
        and value["mints"][1]["issuedAt"] > value["mints"][0]["expiresAt"]
        and value["mints"][2]["issuedAt"] >= value["mints"][1]["issuedAt"]
        and [m["signingKey"] for m in value["mints"]] == ["A", "A", "B"], "App renewal or client phases incomplete")
    for index, mint in enumerate(value["mints"]):
        require(type(mint) is dict and set(mint) == {"ordinal", "issuedAt", "expiresAt", "selection", "permissions", "signingKey"}
            and type(mint["ordinal"]) is int and mint["ordinal"] == index + 1
            and type(mint["issuedAt"]) is int and mint["issuedAt"] > 0 and type(mint["expiresAt"]) is int
            and mint["expiresAt"] - mint["issuedAt"] == (120 if index == 0 else 3600)
            and mint["selection"] == ("name" if index == 0 else "id")
            and mint["permissions"] == fixture.PERMISSIONS, "terminal mint binding differs")
    inventory = value["namedAuditInventory"]
    expected_counts = {START: 18, RELEASE: 18, DENIED: 3, CONNECT_DENIED: 6, RELOAD: 4, REPLACED: 1,
        "operator_catalog.credential.github_app_created": 1, "operator_catalog.application.created": 3,
        "operator_catalog.access_rule.github_created": 2, "operator_catalog.access_rule.revoked": 2}
    require(set(inventory) <= set(expected_counts) | {CONNECT, KEEP_ALIVE, LEASE}
        and all(inventory.get(k) == n for k, n in expected_counts.items())
        and 4 <= inventory.get(LEASE, 0) <= 64 and inventory.get(CONNECT, 0) + inventory.get(KEEP_ALIVE, 0) == 21
        and inventory.get(KEEP_ALIVE, 0) <= 9, "terminal audit inventory differs")
    require(all(type(v) is str and SHA256.fullmatch(v) for v in value["auditAttemptIds"])
        and len(set(value["dispatchLeaseIds"])) == len(value["dispatchLeaseIds"])
        and all(type(v) is str and 0 < len(v) <= 128 for v in value["dispatchLeaseIds"] + value["replacementAuditEventIds"]),
        "terminal audit identifiers differ")
    for key in ("assignedApplicationIds", "assignedRuleIds"):
        ids = value[key]
        require(type(ids) is list and len(ids) == len(set(ids)) == 2 and all(type(v) is str
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", v) for v in ids),
            "two retained assignment identities required")
    wait = value["leaseExpiryWait"]
    require(type(wait) is dict and set(wait) == {"sourceLeaseTtlUpperBoundMs", "minimumPostCommitWaitMs",
            "actualPostCommitWaitMonotonicNs", "remoteInvalidationAcknowledged", "inFlightRequestsRecalled"}
        and type(wait["sourceLeaseTtlUpperBoundMs"]) is int and wait["sourceLeaseTtlUpperBoundMs"] == LEASE_CAP_MS
        and type(wait["minimumPostCommitWaitMs"]) is int and wait["minimumPostCommitWaitMs"] == 5250
        and type(wait["actualPostCommitWaitMonotonicNs"]) is int
        and 5_250_000_000 <= wait["actualPostCommitWaitMonotonicNs"] < 180_000_000_000
        and wait["remoteInvalidationAcknowledged"] is False and wait["inFlightRequestsRecalled"] is False,
        "replacement incorrectly claimed lease recall or skipped expiry")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "app-key-file", "replacement-key-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--expected-initial-revision", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args, check = parser.parse_args(), None
    def expired(*_):
        raise CheckFailure("App examples deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    try:
        require(args.timeout_seconds == 180 and SHA256.fullmatch(args.expected_binary_sha256)
            and 1 <= args.expected_initial_revision <= 3, "App checker bounds differ")
        signal.alarm(args.timeout_seconds)
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = AppExamplesCheck(args)
        result = check.run(); validate_success_result(result)
        check.clean(json.dumps(result).encode())
    except Exception:
        result = {"schema": SCHEMA, "ok": False, "syntheticOnly": True, "realGithubVerified": False,
            "error": "GitHub App example acceptance failed", "phase": check.current_phase if check else None,
            "client": check.current_client if check else None, "completed": check.completed if check else []}
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
