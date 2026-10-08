#!/usr/bin/env python3
"""One-shot acceptance for a NEW, isolated, synthetic operator catalog fixture.

Never launches a stack. Requires the private initializer marker, an exclusive
durable run claim, an empty catalog, and explicit private endpoints/CA files.
Only the new catalog API is mutated; the legacy combined API is not used.
Raw application tokens and provider/admin credentials remain in memory only.
Success proves this private HTTP CONNECT leg, not public TLS/DNS or production.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time
from urllib.parse import urlencode

try:
    from scripts import operator_catalog_feature_checks as features
    from scripts.operator_catalog_feature_checks import release_attempt_pairs
    from scripts.check_operator_demo import (
        AUTHORITY, SHA256, CheckFailure, OperatorDemoCheck, require, token_file,
    )
except ModuleNotFoundError:
    import operator_catalog_feature_checks as features
    from operator_catalog_feature_checks import release_attempt_pairs
    from check_operator_demo import (
        AUTHORITY, SHA256, CheckFailure, OperatorDemoCheck, require, token_file,
    )


PREFIX = "/api/operator-demo"
COLLECTIONS = ("credentials", "applications", "access_rules")
CLAIM_NAME = ".operator-catalog-acceptance.claim"
MARKER = {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True}
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
WARM_MIN_REMAINING_MS = 1000


def claim_fixture(marker: Path, claim: Path) -> None:
    """Fail closed before any API mutation, including after a partial prior run."""
    require(marker.is_absolute() and claim.is_absolute() and claim.name == CLAIM_NAME
            and marker.resolve() == marker and claim.parent.resolve() == claim.parent,
            "explicit non-symlink private marker and claim paths required")
    descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400
                and info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size <= 1024,
                "private fixture marker permissions refused")
        document = json.loads(os.read(descriptor, 1025))
        require(document == MARKER, "synthetic private fixture marker missing")
    finally:
        os.close(descriptor)
    parent = claim.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700
            and parent.st_uid == os.geteuid(), "claim directory must be private and owned")
    try:
        descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise CheckFailure("fixture acceptance already claimed; never retry this runtime") from None
    with os.fdopen(descriptor, "w", encoding="ascii") as target:
        target.write('{"schema":"serverware.operatorCatalogClaim/v1","oneShot":true}\n')
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class OperatorCatalogCheck(OperatorDemoCheck):
    def __init__(self, args):
        self.issued_tokens: list[str] = []
        super().__init__(args)
        self.snapshot = None
        self.observations: list[dict] = []
        self.successes: list[tuple[str, str, str]] = []
        self.mutations: list[tuple[str, str, str]] = []
        self.warm_observations: list[dict] = []

    def clean(self, content: bytes, *, allow_client_token: bool = False) -> None:
        # Even a token-returning response must never repeat any PREVIOUS token.
        super().clean(content, allow_client_token=allow_client_token)
        require(all(token.encode("ascii") not in content for token in self.issued_tokens),
                "previous application token escaped into a response or durable audit")

    def catalog(self):
        snapshot = self.control_json(PREFIX + "/catalog", authenticated=True)
        require(isinstance(snapshot, dict) and snapshot.get("schema") == "serverware.operatorCatalog/v1"
                and snapshot.get("mode") == "operator-development"
                and snapshot.get("productionReady") is False and snapshot.get("hardwareVerified") is False
                and snapshot.get("allowed_upstreams") == ["https://" + AUTHORITY]
                and type(snapshot.get("revision")) is int and snapshot["revision"] >= 1
                and all(isinstance(snapshot.get(key), list) for key in COLLECTIONS),
                "target is not the fixture-only operator catalog")
        policy = snapshot.get("policy", {})
        require(isinstance(policy.get("policy_hash"), str) and SHA256.fullmatch(policy["policy_hash"])
                and type(policy.get("sequence")) is int and policy["sequence"] > 0,
                "catalog signed policy metadata is invalid")
        self.snapshot = snapshot
        return snapshot

    @staticmethod
    def resource(snapshot, collection, identifier):
        rows = [row for row in snapshot[collection] if row.get("id") == identifier]
        require(len(rows) == 1, "catalog resource missing or duplicated")
        return rows[0]

    def mutate(self, route, payload, *, collection, result_key, event, creates=False, token=False,
               authority_changed=False):
        before = self.catalog()
        payload = {**payload, "expected_revision": before["revision"],
                   "expected_policy_hash": before["policy"]["policy_hash"]}
        status, result = self.json_request(self.control, PREFIX + route, context=self.control_ca,
            method="POST", payload=payload, authenticated=True, creation=token)
        require(status == (201 if creates else 200) and isinstance(result, dict),
                "catalog mutation returned an unexpected status or document")
        issued = result.pop("client_token", None)
        require((isinstance(issued, str) and TOKEN.fullmatch(issued) is not None) if token else issued is None,
                "catalog one-time token contract differs")
        if token:
            require(issued not in self.issued_tokens, "token rotation reused a prior verifier preimage")
            self.issued_tokens.append(issued)
        self.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        resource = result.get(result_key)
        require(isinstance(resource, dict) and isinstance(resource.get("id"), str)
                and result.get("revision") == before["revision"] + 1,
                "mutation resource or revision differs")
        after = self.catalog()
        require(after["revision"] == result["revision"]
                and after["policy"]["policy_hash"] == result.get("policy", {}).get("policy_hash")
                and self.resource(after, collection, resource["id"])["version"] == resource.get("version"),
                "mutation did not survive fresh catalog read")
        old_policy, new_policy = before["policy"], after["policy"]
        require((new_policy["policy_hash"] != old_policy["policy_hash"]
                 and new_policy["sequence"] == old_policy["sequence"] + 1) if authority_changed else
                (new_policy["policy_hash"] == old_policy["policy_hash"]
                 and new_policy["sequence"] == old_policy["sequence"]),
                "store-only or authority-changing policy publication differs")
        self.mutations.append((event, resource["id"], new_policy["policy_hash"]))
        self.policy_hash = new_policy["policy_hash"]
        return resource, issued, result

    def wait_catalog_loaded(self, label):
        while True:
            snapshot, health = self.catalog(), self.health()
            policy = snapshot["policy"]
            if (policy.get("activation") == "active" and policy["policy_hash"] == self.policy_hash
                    == policy.get("loaded_policy_hash") == health.get("policy_hash")
                    == health.get("policy_shadow", {}).get("operator_policy_sha256")):
                self.observations.append({"stage": label, "revision": snapshot["revision"],
                    "policyHash": self.policy_hash, "sequence": policy["sequence"]})
                return snapshot, health
            time.sleep(min(0.25, self.timeout()))

    def count(self):
        # Global and per-run counts must agree: a different run cannot hide traffic.
        status, document = self.json_request(self.upstream,
            "/_test/request-count?" + urlencode({"method": "GET", "path": "/echo"}),
            context=self.upstream_ca)
        require(status == 200 and isinstance(document, dict) and type(document.get("count")) is int,
                "global upstream dispatch counter unavailable")
        count = document["count"]
        require(count == self.upstream_count("GET"), "unexpected traffic in the isolated fixture")
        return count

    def denied_without_dispatch(self, token, *, warm=None):
        before = self.count()
        self.tunnel(token, expected_status=403)
        require(self.count() == before, "denied application token dispatched upstream")
        if warm is not None:
            checked = time.time_ns() // 1_000_000
            elapsed = time.monotonic_ns() - warm["_captured_monotonic_ns"]
            window_ms = warm["denialDeadlineEpochMs"] - warm["capturedAtEpochMs"]
            require(warm["capturedAtEpochMs"] <= checked < warm["denialDeadlineEpochMs"]
                    and 0 <= elapsed < window_ms * 1_000_000,
                    "old token denial was not proved before captured lease expiry")
            warm["denialVerifiedAtEpochMs"] = checked
            warm["denialElapsedMonotonicMs"] = elapsed // 1_000_000
            self.warm_observations.append({key: value for key, value in warm.items() if not key.startswith("_")})

    def observe_live_lease(self, stage, application, rule, credential, *, minimum_scopes):
        health = self.health()
        # This minimum excludes expired entries and is NOT scoped to a principal.
        # Bind it to this app's real dispatchSecret issuance receipt as well.
        receipts = [row for row in self.audit() if row.get("event_type") == "data_plane.credential_lease.issued"
            and all(row.get("event", {}).get(key) == value for key, value in {
                "purpose": "dispatchSecret", "principal_id": application["principal_id"],
                "route_id": rule["route_id"], "credential_id": credential["id"],
                "policy_hash": self.policy_hash, "data_plane_binary_digest": self.args.expected_binary_sha256,
            }.items())]
        now, monotonic = time.time_ns() // 1_000_000, time.monotonic_ns()
        expiry = health.get("credential_lease_earliest_expiry_epoch_ms")
        require(type(expiry) is int and expiry > now + WARM_MIN_REMAINING_MS
                and health.get("policy_hash") == self.policy_hash
                and type(health.get("credential_leases")) is int and health["credential_leases"] >= minimum_scopes
                and health.get("credential_generation_hot_scopes", 0) >= minimum_scopes,
                "live credential lease freshness window unavailable")
        valid = [row for row in receipts if type(row["event"].get("issued_at_epoch_ms")) is int
            and type(row["event"].get("expires_at_epoch_ms")) is int
            and row["event"]["issued_at_epoch_ms"] <= now
            and row["event"]["expires_at_epoch_ms"] > now + WARM_MIN_REMAINING_MS]
        require(bool(valid), "app-scoped live dispatch lease receipt unavailable")
        receipt = max(valid, key=lambda row: row["event"]["expires_at_epoch_ms"])
        scoped_expiry = receipt["event"]["expires_at_epoch_ms"]
        return {"stage": stage, "principalId": application["principal_id"], "routeId": rule["route_id"],
            "policyHash": self.policy_hash, "capturedAtEpochMs": now, "_captured_monotonic_ns": monotonic,
            "healthEarliestUnexpiredLeaseEpochMs": expiry, "scopedLeaseIssuedAtEpochMs": receipt["event"]["issued_at_epoch_ms"],
            "scopedLeaseExpiryEpochMs": scoped_expiry, "scopedLeaseAuditEventId": receipt["id"],
            "denialDeadlineEpochMs": min(expiry, scoped_expiry),
            "credentialLeases": health["credential_leases"], "hotScopes": health["credential_generation_hot_scopes"]}

    def injected(self, token, application, rule):
        self.client_token = token
        before = self.count()
        digest = "sha256:" + hashlib.sha256(("Bearer " + self.credential).encode("ascii")).hexdigest()
        status, payload = self.request("/echo?" + urlencode({"expectedAuthorizationSha256": digest}))
        require(status == 200 and isinstance(payload, dict)
                and set(payload) == features.PROJECTED_FIELDS
                and payload.get("authorization_present") is True and payload.get("authorization_scheme") == "Bearer"
                and payload.get("authorization_matches_expected") is True
                and payload.get("proxy_authorization_seen") is False
                and payload.get("path") == "/echo" and payload.get("method") == "GET"
                and digest not in json.dumps(payload), "exact provider injection or proxy-token stripping failed")
        require(self.count() == before + 1, "authorized request dispatch count differs")
        self.successes.append((application["principal_id"], rule["route_id"], self.policy_hash))

    def verify_catalog_audit(self):
        return features.verify_audit(self)

    def run(self):
        self.health()  # Profile and exact binary before loading the administrator token.
        self.admin_token = token_file(self.args.admin_token_file)
        snapshot = self.catalog()
        require(snapshot["revision"] == 1 and all(not snapshot[key] for key in COLLECTIONS)
                and all(snapshot["limits"][key]["retained"] == 0 for key in COLLECTIONS),
                "acceptance requires a fresh empty catalog without retained admission history")
        require(self.count() == 0, "acceptance requires a fresh unused upstream fixture")
        self.results.append("fresh_private_synthetic_catalog_and_exact_operator_binary")
        credential, _, _ = self.mutate("/credentials", {"name": self.run_id + "-shared",
            "auth_type": "bearer", "secret": self.credential}, collection="credentials",
            result_key="credential", event="operator_catalog.credential.created", creates=True)
        applications, tokens, rules = [], [], []
        for number in (1, 2):
            application, token, _ = self.mutate("/applications", {"name": self.run_id + "-app" + str(number),
                "token_lifetime_seconds": 3600}, collection="applications", result_key="application",
                event="operator_catalog.application.created", creates=True, token=True)
            require(application.get("token_generation") == 1 and application.get("token_status") == "valid"
                    and application.get("access_status") == "unassigned"
                    and abs(application.get("token_expires_at_epoch_ms", 0) - (time.time() + 3600) * 1000) < 15000,
                    "new application expiry or unassigned state differs")
            applications.append(application)
            tokens.append(token)
            self.denied_without_dispatch(token)
        self.results.append("store_only_credential_and_applications_do_not_grant_access_or_resign_policy")
        for application in applications:
            rule, _, _ = self.mutate("/access-rules", {"name": application["name"] + "-echo",
                "application_id": application["id"], "credential_id": credential["id"],
                "upstream_url": "https://" + AUTHORITY + "/echo", "methods": ["GET"],
                "request_fields": [], "response_fields": ["method", "path", "authorization_present",
                    "authorization_scheme", "authorization_matches_expected", "proxy_authorization_seen"],
                "query_keys": ["expectedAuthorizationSha256"], "allowed_headers": ["accept", "user-agent"],
                "response_mode": "projected_json"}, collection="access_rules", result_key="access_rule",
                event="operator_catalog.access_rule.created", creates=True, authority_changed=True)
            rules.append(rule)
        self.wait_catalog_loaded("two_rules")
        self.denied_without_dispatch(None)
        self.denied_without_dispatch(self.wrong_token)
        for _ in range(2):
            for application, token, rule in zip(applications, tokens, rules):
                self.injected(token, application, rule)
        revoke_warm = self.observe_live_lease("before_app1_revoke", applications[0], rules[0], credential, minimum_scopes=2)
        self.results.append("one_shared_credential_two_apps_two_rules_both_200_with_warm_leases")
        _, _, revoked = self.mutate("/applications/revoke", {"id": applications[0]["id"]},
            collection="applications", result_key="application", event="operator_catalog.application.revoked",
            authority_changed=True)
        require(revoked.get("affected_rule_ids") == [rules[0]["id"]], "application revoke affected sibling rules")
        snapshot, _ = self.wait_catalog_loaded("app1_revoked")
        require(self.resource(snapshot, "applications", applications[0]["id"])["status"] == "revoked"
                and self.resource(snapshot, "access_rules", rules[0]["id"])["enforcement"] == "revoked"
                and self.resource(snapshot, "access_rules", rules[1]["id"])["enforcement"] == "active",
                "per-application revocation state differs")
        self.denied_without_dispatch(tokens[0], warm=revoke_warm)
        self.injected(tokens[1], applications[1], rules[1])
        self.results.append("warm_app1_revoked_403_no_dispatch_while_app2_still_200")
        rotate_warm = self.observe_live_lease("before_app2_rotate", applications[1], rules[1], credential, minimum_scopes=1)
        rotated, replacement, _ = self.mutate("/applications/rotate-token",
            {"id": applications[1]["id"], "token_lifetime_seconds": 3600}, collection="applications",
            result_key="application", event="operator_catalog.application.token_rotated", token=True,
            authority_changed=True)
        require(rotated.get("token_generation") == 2 and rotated.get("principal_id") == applications[1]["principal_id"],
                "rotation changed identity or failed to advance token generation")
        snapshot, _ = self.wait_catalog_loaded("app2_rotated")
        self.denied_without_dispatch(tokens[1], warm=rotate_warm)
        self.denied_without_dispatch(tokens[0])
        self.injected(replacement, applications[1], rules[1])
        retained = self.resource(snapshot, "credentials", credential["id"])
        require(len(snapshot["credentials"]) == 1 and retained["status"] == "active"
                and retained["version"] == credential["version"] and retained["active_rule_count"] == 1
                and len(snapshot["applications"]) == 2 and len(snapshot["access_rules"]) == 2
                and self.count() == 6, "shared credential, resource retention, or total dispatch count differs")
        self.results.append("app2_old_token_403_no_dispatch_new_token_200_shared_credential_unchanged")
        features.checkpoint(self, "lifecycle")
        feature_app, feature_rule = features.run_features(self, credential)
        audit_ids, attempt_ids = self.verify_catalog_audit()
        result = {"ok": True, "schema": "serverware.operatorCatalogCheck/v1", "mode": "operator-development",
            "productionReady": False, "hardwareVerified": False, "publicDnsVerified": False,
            "proxyTransport": "private-http-connect-leg" if self.proxy.scheme == "http" else "verified-private-https-edge",
            "originTlsVerified": True, "runId": self.run_id, "checks": self.results,
            "credentialId": credential["id"], "applicationIds": [row["id"] for row in applications] + [feature_app],
            "ruleIds": [row["id"] for row in rules] + [feature_rule], "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
            **features.safe_evidence(self), "upstreamDispatches": 9, "responsesReleased": 7, "responsesBlocked": 2,
            "durableAuditEventIds": audit_ids, "auditedRequestAttemptIds": attempt_ids}
        self.clean(json.dumps(result, sort_keys=True).encode("utf-8"))
        return result


def run_checks(args):
    check = None
    try:
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256),
                "expected binary digest must be exact lowercase SHA-256")
        require(type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 180,
                "acceptance timeout must be between 10 and 180 seconds")
        # A failed/partial invocation consumes the runtime; never retry mutations.
        claim_fixture(args.fixture_marker_file, args.run_claim_file)
        check = OperatorCatalogCheck(args)
        return check.run()
    except Exception as error:
        evidence = {}
        if check is not None:
            try:
                evidence = features.safe_evidence(check)
            except Exception:
                evidence = {"safeEvidenceUnavailable": True}
        return {"ok": False, "mode": "operator-development", "checks": list(check.results) if check else [],
            **evidence,
            "error": str(error) if isinstance(error, CheckFailure) else type(error).__name__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file", "fixture-marker-file", "run-claim-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise CheckFailure("catalog acceptance exceeded its process deadline")

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
