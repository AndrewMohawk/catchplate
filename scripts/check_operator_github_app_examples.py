#!/usr/bin/env python3
"""One fresh GitHub App -> real lease/Rust -> three ordinary SDK acceptance.

No stack launch, dependencies, clock patching, cache clearing or command retry.
Provisioning uses the real authenticated catalog API and HTTPS protocol.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import check_operator_github_examples as stock
from scripts import operator_github_app_examples_fixture as fixture
from scripts.check_operator_catalog import COLLECTIONS, claim_fixture, features
from scripts.check_operator_demo import SHA256, CheckFailure, require, token_file
from scripts.check_operator_ordinary_client import BLOCK, CONNECT, DENIED, LEASE, RELEASE, RELOAD, START, digest
from scripts.check_operator_github import CONNECT_DENIED, KEEP_ALIVE
from scripts.check_operator_key_replacement import authority_projection

SCHEMA = "serverware.privateGithubAppExamplesCheck/v1"
PHASES = {"initial", "connection", "grant", "read_initial", "wrong_app", "wrong_repo",
          "expiry_wait", "read_renewed", "revoke", "revoked", "audit"}


def read_key(path):
    require(path == Path("/client-secrets/github-app.pem"), "fixed synthetic App key required")
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
        and len(value["auth"]) <= 6 and len(value["attempts"]) <= 12 and len(value["mints"]) <= 2,
        "App provider observations differ")
    all_rows = value["auth"] + value["attempts"]
    require(sorted(row.get("ordinal") for row in all_rows) == list(range(1, value["total"] + 1))
        and all(row.get("accepted") is True for row in all_rows), "provider refused or lost an arrival")
    for index, row in enumerate(value["auth"]):
        step = index % 3
        require(set(row) == {"ordinal", "accepted", "kind", "cycle", "method", "status", "jwtVerified"}
            and row["kind"] == ("installation", "mint", "repositories")[step]
            and type(row["cycle"]) is int and row["cycle"] == index // 3 + 1
            and row["method"] == ("POST" if step == 1 else "GET")
            and type(row["status"]) is int and row["status"] == (201 if step == 1 else 200)
            and row["jwtVerified"] is (step < 2), "App provisioning oracle differs")
    for index, mint in enumerate(value["mints"]):
        require(type(mint) is dict and set(mint) == {"ordinal", "issuedAt", "expiresAt", "selection", "permissions"}
            and type(mint["ordinal"]) is int and mint["ordinal"] == index + 1
            and type(mint["issuedAt"]) is int and type(mint["expiresAt"]) is int
            and mint["issuedAt"] > 0 and mint["expiresAt"] - mint["issuedAt"] == (fixture.TOKEN_SECONDS if index == 0 else 3600)
            and mint["selection"] == ("name" if index == 0 else "id")
            and mint["permissions"] == fixture.PERMISSIONS, "scoped mint observation differs")
    if len(value["mints"]) == 2:
        require(value["mints"][1]["issuedAt"] > value["mints"][0]["expiresAt"], "original token expiry was not crossed")
    for index, row in enumerate(value["attempts"]):
        require(set(row) == stock.ROW_KEYS | {"cycle"} and type(row["cycle"]) is int
            and row["cycle"] == index // 6 + 1, "App resource cycle differs")
        original = {k: v for k, v in row.items() if k != "cycle"}
        # PAT's exact raw request/response grammar, not its credential source.
        original["ordinal"] = index % 6 + 1
        stock.validate_row(original, index % 6 + 1, fixture.examples.CLIENTS[(index % 6) // 2], index % 2 + 1)
    return value


def match_pairs(rows, wire, scope, credential_id):
    """Repeated canonical requests still require distinct complete attempt IDs."""
    expected = Counter((w["requestDigest"], w["operationDigest"], w["responseBodySha256"], w["responseBodyBytes"]) for w in wire)
    pairs = {}
    for row in rows:
        if row["event_type"] not in {START, RELEASE}:
            continue
        event, kind = row["event"], row["event_type"]
        attempt = event.get("attempt_id")
        require(type(attempt) is str and SHA256.fullmatch(attempt) and event.get("flow_id") == attempt
            and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
            and event.get("credential_ref") == credential_id and type(event.get("credential_version")) is int
            and event["credential_version"] == 1 and event.get("method") == "GET"
            and event.get("body_sha256") == digest(b"")
            and (event.get("request_digest"), event.get("operation_digest")) in {key[:2] for key in expected},
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
        key = (release.get("request_digest"), release.get("operation_digest"),
            release.get("response_body_sha256"), release.get("response_body_bytes"))
        require(start.get("outcome") == "release_started" and release.get("outcome") == "released"
            and (start.get("request_digest"), start.get("operation_digest")) == key[:2]
            and release.get("upstream_status") == 200 and expected[key] > 0,
            "App request/response commitments differ")
        validation = release.get("response_validation", {})
        require(validation.get("ok") is True and validation.get("body_bytes_preserved") is True
            and validation.get("mode") == "bufferedJsonOrEmpty204V2", "App response guard differs")
        expected[key] -= 1
        complete.append({"attemptId": attempt, "startId": pair["start"]["id"], "releaseId": pair["release"]["id"]})
    return complete if len(complete) == len(wire) and not any(expected.values()) else None


def validate_revoked_credential(before, after):
    """Only the sole grant's derived count changes; custody stays identical."""
    require(type(before) is dict and type(after) is dict
        and type(before.get("active_rule_count")) is int and before["active_rule_count"] == 1
        and type(after.get("active_rule_count")) is int and after["active_rule_count"] == 0
        and type(before.get("credential_generation")) is int and before["credential_generation"] == 1
        and type(after.get("credential_generation")) is int and after["credential_generation"] == 1,
        "App credential generation or revoked grant count differs")
    expected = {**before, "active_rule_count": 0}
    # JSON equality also distinguishes bool/int/float substitutions, retaining
    # all current and future public fields rather than a selected subset.
    require(json.dumps(after, sort_keys=True) == json.dumps(expected, sort_keys=True),
        "App credential changed during rule revocation")


class AppExamplesCheck(stock.ExamplesCheck):
    def __init__(self, args):
        self.app_pem = None
        super().__init__(args)
        self.current_phase, self.pairs = "initial", []
        self.app_pem = read_key(args.app_key_file)

    def clean(self, content, *, allow_client_token=False):
        super().clean(content, allow_client_token=allow_client_token)
        sensitive = list(fixture.TOKENS)
        if self.app_pem:
            sensitive += [self.app_pem, *[line for line in self.app_pem.splitlines() if not line.startswith("-----")]]
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
        if phase in {"read_initial", "read_renewed"}:
            require(code == 0 and not stderr and json.loads(stdout) == stock.expected_output(client), "App SDK read failed")
        else:
            require(code == 1, "App SDK denial did not fail closed")
        self.completed.append({"client": client, "phase": phase, "exitCode": code})

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
        exact.update({START: 12, RELEASE: 12, DENIED: 3, CONNECT_DENIED: 6, RELOAD: 2})
        require(set(counts) <= set(exact) | {CONNECT, KEEP_ALIVE, LEASE}
            and all(counts[k] == v for k, v in exact.items()) and counts[LEASE] <= 64
            and counts[CONNECT] + counts[KEEP_ALIVE] == 15 and counts[KEEP_ALIVE] <= 6,
            "final App audit inventory differs")
        pairs = match_pairs(rows, self.wire, scope, credential["id"])
        require(pairs is not None and {p["attemptId"] for p in pairs} == {p["attemptId"] for p in self.pairs}
            and len(self.pairs) == 12, "App attempts were lost or reused")
        leases = []
        for row in rows:
            event, kind = row["event"], row["event_type"]
            if kind == LEASE:
                require(event.get("outcome") == "issued" and event.get("status_code") == 200
                    and tuple(event.get(k) for k in ("principal_id", "route_id", "policy_hash")) == scope
                    and event.get("credential_id") == credential["id"]
                    and event.get("data_plane_binary_digest") == self.args.expected_binary_sha256
                    and event.get("purpose") in {"generationMetadata", "dispatchSecret"}, "App lease authority differs")
                if event["purpose"] == "dispatchSecret":
                    require(event.get("expected_credential_version") == 1, "App refresh changed stored generation")
                    leases.append(row["id"])
            elif kind in {CONNECT, KEEP_ALIVE}:
                require(event.get("target") == "api.github.com:443" and event.get("principal_id") == scope[0]
                    and event.get("policy_hash") == scope[2], "App CONNECT binding differs")
            elif kind == RELOAD:
                # With no active grants the schema still has operator.empty:
                # one credential-free route for a permanently expired principal.
                require((event.get("previous_policy_hash"), event.get("policy_hash"), event.get("routes")) in {
                    (self.initial_policy_hash, scope[2], 1), (scope[2], revoked_hash, 1)}, "App policy reload differs")
        require(len(leases) >= 2 and set(self.mutations) <= {(r["event_type"], r["event"].get("resource_id"),
            r["event"].get("policy_hash")) for r in rows}, "App mutation or dispatch evidence missing")
        verified = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(verified.get("ok") is True and verified.get("complete") is True and self.audit_drained(), "App audit chain incomplete")
        return {"namedAuditInventory": dict(sorted(counts.items())), "auditAttemptIds": sorted(p["attemptId"] for p in pairs),
            "dispatchLeaseIds": leases}

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
            event="operator_catalog.application.created", creates=True, token=True)[:2] for label in ("assigned", "unassigned")]
        application, token = apps[0]
        rule, _, _ = self.mutate("/access-rules/github", {"name": self.run_id + "-read", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": "github_issues_read_v1",
            "repository": {"owner": fixture.examples.OWNER, "name": fixture.examples.REPO}}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.github_created", creates=True, authority_changed=True)
        self.wait_catalog_loaded("assigned")
        pins, scope = self.warm_cas_snapshot(), (application["principal_id"], rule["route_id"], self.policy_hash)
        for cycle, phase in ((1, "read_initial"), (2, "read_renewed")):
            if cycle == 2:
                for client in fixture.examples.CLIENTS:
                    self.negative(client, "wrong_app", *apps[1]); self.negative(client, "wrong_repo", *apps[0])
                self.wait_original_expiry()
            for client in fixture.examples.CLIENTS:
                self.unchanged(pins)
                before = features.audit_cutoff(self.audit())
                first_index = len(self.wire)
                self.example(client, phase, application, token)
                observed = self.observe()
                require(len(observed["attempts"]) == first_index + 2 and len(observed["mints"]) == cycle, "SDK count or renewal differs")
                current = []
                for row in observed["attempts"][first_index:]:
                    request, operation = stock.canonical_digests(row, scope, credential["id"], self.proxy.address)
                    current.append({"requestDigest": request, "operationDigest": operation,
                        "responseBodySha256": row["responseBodySha256"], "responseBodyBytes": row["responseBodyBytes"]})
                self.wire.extend(current)
                self.wait_pairs(before, current, scope, credential["id"])
        self.unchanged(pins)
        self.current_phase = "revoke"
        self.mutate("/access-rules/revoke", {"id": rule["id"]}, collection="access_rules", result_key="access_rule",
            event="operator_catalog.access_rule.revoked", authority_changed=True)
        self.wait_catalog_loaded("revoked")
        revoked = self.warm_cas_snapshot()
        require(self.resource(revoked, "access_rules", rule["id"])["status"] == "revoked",
            "App rule revocation did not persist")
        validate_revoked_credential(self.resource(pins, "credentials", credential["id"]),
            self.resource(revoked, "credentials", credential["id"]))
        for client in fixture.examples.CLIENTS:
            self.negative(client, "revoked", application, token)
        self.current_phase = "audit"
        evidence = self.audit_result(baseline, scope, credential, self.policy_hash)
        observed = self.observe()
        require(observed["total"] == 18 and len(observed["auth"]) == 6 and len(observed["attempts"]) == 12,
            "final App provider counts differ")
        return {"schema": SCHEMA, "ok": True, "syntheticOnly": True, "realGithubVerified": False, "productionReady": False,
            "actualExampleEntrypoints": True, "providerAttempts": 12, "provisioningAttempts": 6, "mints": observed["mints"],
            "releases": 12, "deniedBeforeDispatch": 9, "storedGenerationUnchanged": True,
            "dataPlaneBinaryDigest": self.args.expected_binary_sha256, "goExampleSha256": self.args.expected_go_sha256,
            "exampleSourceSha256": self.example_sources, "completed": self.completed,
            "pythonTrust": "client-only-union-not-independent-roots", **evidence}


def validate_success_result(value):
    keys = {"schema", "ok", "syntheticOnly", "realGithubVerified", "productionReady", "actualExampleEntrypoints",
        "providerAttempts", "provisioningAttempts", "mints", "releases", "deniedBeforeDispatch", "storedGenerationUnchanged",
        "dataPlaneBinaryDigest", "goExampleSha256", "exampleSourceSha256", "completed", "pythonTrust",
        "namedAuditInventory", "auditAttemptIds", "dispatchLeaseIds"}
    require(type(value) is dict and set(value) == keys and value.get("schema") == SCHEMA and value.get("ok") is True
        and value.get("syntheticOnly") is True and value.get("actualExampleEntrypoints") is True
        and value.get("realGithubVerified") is False and value.get("productionReady") is False
        and value.get("storedGenerationUnchanged") is True
        and [value.get(k) for k in ("providerAttempts", "provisioningAttempts", "releases", "deniedBeforeDispatch")] == [12, 6, 12, 9]
        and len(value.get("auditAttemptIds", [])) == len(set(value.get("auditAttemptIds", []))) == 12
        and len(value.get("dispatchLeaseIds", [])) >= 2, "App checker result incomplete")
    require(SHA256.fullmatch(value["dataPlaneBinaryDigest"]) and len(value["goExampleSha256"]) == 64
        and set(value["exampleSourceSha256"]) == set(stock.SOURCE_FILES)
        and value["pythonTrust"] == "client-only-union-not-independent-roots"
        and all(type(v) is int and v > 0 for v in value["namedAuditInventory"].values()), "App result identities differ")
    expected = [{"client": client, "phase": phase, "exitCode": 0} for client in fixture.examples.CLIENTS for phase in ("read_initial",)]
    expected += [{"client": client, "phase": phase, "exitCode": 1} for client in fixture.examples.CLIENTS for phase in ("wrong_app", "wrong_repo")]
    expected += [{"client": client, "phase": "read_renewed", "exitCode": 0} for client in fixture.examples.CLIENTS]
    expected += [{"client": client, "phase": "revoked", "exitCode": 1} for client in fixture.examples.CLIENTS]
    require(value.get("completed") == expected and len(value.get("mints", [])) == 2
        and value["mints"][1]["issuedAt"] > value["mints"][0]["expiresAt"], "App renewal or client phases incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "proxy-ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file", "app-key-file"):
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
