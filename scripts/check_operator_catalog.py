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
WARM_STAGES = {"before_app1_revoke", "before_app2_rotate"}
WARM_ID = re.compile(r"[A-Za-z0-9._:-]{1,256}\Z")


def _warm_integer(value):
    """Telemetry admits bounded numbers only, never arbitrary response values."""
    return value if type(value) is int and 0 <= value <= (1 << 64) - 1 else None


def _warm_clock():
    return {"epochMs": time.time_ns() // 1_000_000, "monotonicNs": time.monotonic_ns()}


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
        self.warm_lease_checks: list[dict] = []
        self.warm_denial_checks: list[dict] = []

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
        resource, issued, result = self.submit_mutation(before, route, payload, result_key=result_key,
            creates=creates, token=token, authority_changed=authority_changed)
        after = self.catalog()
        self.finalize_mutation(result, after, collection=collection, result_key=result_key, event=event)
        return resource, issued, result

    def submit_mutation(self, before, route, payload, *, result_key, creates=False, token=False,
                        authority_changed=False):
        """One POST against an already read CAS snapshot; never retries a mutation."""
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
                and ("id" not in payload or resource["id"] == payload["id"])
                and type(resource.get("version")) is int and resource["version"] > 0
                and type(result.get("revision")) is int and result["revision"] == before["revision"] + 1,
                "mutation resource or revision differs")
        old_policy, new_policy = before["policy"], result.get("policy", {})
        require(isinstance(new_policy, dict)
                and isinstance(new_policy.get("policy_hash"), str) and SHA256.fullmatch(new_policy["policy_hash"])
                and type(new_policy.get("sequence")) is int and new_policy["sequence"] > 0,
                "mutation signed policy metadata is invalid")
        require((new_policy["policy_hash"] != old_policy["policy_hash"]
                 and new_policy["sequence"] == old_policy["sequence"] + 1) if authority_changed else
                (new_policy["policy_hash"] == old_policy["policy_hash"]
                 and new_policy["sequence"] == old_policy["sequence"]),
                "store-only or authority-changing policy publication differs")
        return resource, issued, result

    def finalize_mutation(self, result, after, *, collection, result_key, event):
        """Record acceptance only after the mandatory fresh persistence checks."""
        resource, new_policy = result[result_key], result["policy"]
        require(after["revision"] == result["revision"]
                and after["policy"]["policy_hash"] == new_policy["policy_hash"]
                and after["policy"]["sequence"] == new_policy["sequence"]
                and self.resource(after, collection, resource["id"])["version"] == resource.get("version"),
                "mutation did not survive fresh catalog read")
        self.mutations.append((event, resource["id"], new_policy["policy_hash"]))
        self.policy_hash = new_policy["policy_hash"]

    def warm_cas_snapshot(self):
        snapshot = self.catalog()
        policy = snapshot["policy"]
        require(policy["policy_hash"] == self.policy_hash == policy.get("loaded_policy_hash")
                and policy.get("activation") == "active", "warm CAS snapshot is not the current loaded policy")
        return snapshot

    def wait_health_loaded(self, expected_policy_hash):
        while True:
            health = self.health()
            if health.get("policy_hash") == expected_policy_hash == health.get("policy_shadow", {}).get("operator_policy_sha256"):
                return health
            time.sleep(min(0.25, self.timeout()))

    def wait_catalog_loaded(self, label, *, expected_mutation=None):
        expected_hash = self.policy_hash if expected_mutation is None else expected_mutation["policy"]["policy_hash"]
        while True:
            snapshot, health = self.catalog(), self.health()
            policy = snapshot["policy"]
            if expected_mutation is not None:
                require(snapshot["revision"] == expected_mutation["revision"]
                        and policy["policy_hash"] == expected_hash
                        and policy["sequence"] == expected_mutation["policy"]["sequence"],
                        "warm mutation changed before persistence verification")
            if (policy.get("activation") == "active" and policy["policy_hash"] == expected_hash
                    == policy.get("loaded_policy_hash") == health.get("policy_hash")
                    == health.get("policy_shadow", {}).get("operator_policy_sha256")):
                self.observations.append({"stage": label, "revision": snapshot["revision"],
                    "policyHash": expected_hash, "sequence": policy["sequence"]})
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
        if warm is None:
            before = self.count()
            self.tunnel(token, expected_status=403)
            require(self.count() == before, "denied application token dispatched upstream")
            return

        observations = getattr(self, "warm_denial_checks", None)
        if observations is None:
            observations = self.warm_denial_checks = []
        require(len(observations) < 2, "warm denial observation bound exceeded")
        safe_id = lambda value: value if isinstance(value, str) and WARM_ID.fullmatch(value) else None
        stage = warm.get("stage")
        observation = {"stage": stage if isinstance(stage, str) and stage in WARM_STAGES else "other_warm_observation",
            "principalId": safe_id(warm.get("principalId")), "routeId": safe_id(warm.get("routeId")),
            "scopedLeaseAuditEventId": safe_id(warm.get("scopedLeaseAuditEventId")),
            "capturedAtEpochMs": _warm_integer(warm["capturedAtEpochMs"]),
            "capturedMonotonicNs": _warm_integer(warm["_captured_monotonic_ns"]),
            "healthEarliestUnexpiredLeaseEpochMs": _warm_integer(warm.get("healthEarliestUnexpiredLeaseEpochMs")),
            "scopedLeaseExpiryEpochMs": _warm_integer(warm.get("scopedLeaseExpiryEpochMs")),
            "denialDeadlineEpochMs": _warm_integer(warm["denialDeadlineEpochMs"]),
            "expectedStatus": 403, "headersValidated": False, "completed": False,
            "conditions": {}, "failedConjuncts": []}
        self.clean(json.dumps(observation, sort_keys=True).encode("utf-8"))
        observations.append(observation)

        def timed_phase(name, operation):
            timing = observation[name] = {"started": _warm_clock(), "completed": False}
            try:
                result = operation()
                timing["completed"] = True
                return result
            finally:
                timing["finished"] = _warm_clock()
                timing["elapsedMonotonicNs"] = timing["finished"]["monotonicNs"] - timing["started"]["monotonicNs"]
                observation["conditions"][name + "_completed"] = timing["completed"]
                if not timing["completed"]:
                    observation["failedConjuncts"].append(name + "_completed")

        before = timed_phase("preCount", self.count)
        observation["beforeCount"] = _warm_integer(before)
        timed_phase("connect403", lambda: self.tunnel(token, expected_status=403))
        observation["headersValidated"] = True
        # The successful return proves complete, validated CONNECT 403 headers,
        # not a complete response body. This conservative timestamp precedes the
        # independent post-count reads, whose latency is not denial latency.
        denied_at = observation["connect403"]["finished"]
        checked = denied_at["epochMs"]
        elapsed = denied_at["monotonicNs"] - warm["_captured_monotonic_ns"]
        window_ms = warm["denialDeadlineEpochMs"] - warm["capturedAtEpochMs"]
        timing_conditions = {
            "wall_not_before_capture": warm["capturedAtEpochMs"] <= checked,
            "wall_before_original_expiry": checked < warm["denialDeadlineEpochMs"],
            "monotonic_nonnegative": 0 <= elapsed,
            "monotonic_before_original_window": elapsed < window_ms * 1_000_000,
        }
        observation["conditions"].update(timing_conditions)
        observation["failedConjuncts"].extend(name for name, passed in timing_conditions.items() if not passed)
        observation["denialElapsedMonotonicNs"] = elapsed
        observation["denialRemainingWallMs"] = warm["denialDeadlineEpochMs"] - checked
        # Even a late denial still needs the independent no-dispatch observation.
        # count() continues to require agreement of global and per-run counters.
        after = timed_phase("postCount", self.count)
        observation["afterCount"] = _warm_integer(after)
        observation["conditions"]["upstream_count_unchanged"] = after == before
        if after != before:
            observation["failedConjuncts"].append("upstream_count_unchanged")
        observation["comparison"] = _warm_clock()
        observation["completed"] = True
        require(after == before, "denied application token dispatched upstream: upstream_count_unchanged")
        require(all(timing_conditions.values()),
                "old token denial was not proved before captured lease expiry: "
                + ",".join(name for name, passed in timing_conditions.items() if not passed))
        warm["denialVerifiedAtEpochMs"] = checked
        warm["denialElapsedMonotonicMs"] = elapsed // 1_000_000
        self.warm_observations.append({key: value for key, value in warm.items() if not key.startswith("_")})

    def observe_live_lease(self, stage, application, rule, credential, *, minimum_scopes):
        require(type(minimum_scopes) is int and 1 <= minimum_scopes <= 2,
                "unexpected warm lease observation scope")
        observations = getattr(self, "warm_lease_checks", None)
        if observations is None:
            observations = self.warm_lease_checks = []
        require(len(observations) < 2, "warm lease observation bound exceeded")
        safe_id = lambda value: value if isinstance(value, str) and WARM_ID.fullmatch(value) else None
        safe_stage = stage if isinstance(stage, str) and stage in WARM_STAGES else "other_warm_observation"
        observation = {"stage": safe_stage, "principalId": safe_id(application["principal_id"]),
            "routeId": safe_id(rule["route_id"]), "credentialId": safe_id(credential["id"]),
            "minimumScopes": minimum_scopes, "minimumRemainingMsExclusive": WARM_MIN_REMAINING_MS,
            "completed": False, "conditions": {}, "failedConjuncts": []}
        self.clean(json.dumps(observation, sort_keys=True).encode("utf-8"))
        observations.append(observation)

        def timed_read(name, operation):
            timing = observation[name] = {"started": _warm_clock(), "completed": False}
            try:
                result = operation()
                timing["completed"] = True
                return result
            finally:
                timing["finished"] = _warm_clock()
                timing["elapsedMonotonicNs"] = timing["finished"]["monotonicNs"] - timing["started"]["monotonicNs"]
                if not timing["completed"]:
                    observation["failedConjuncts"] = [name + "_completed"]

        health = timed_read("healthFetch", self.health)
        # This minimum excludes expired entries and is NOT scoped to a principal.
        # Bind it to this app's real dispatchSecret issuance receipt as well.
        events = timed_read("auditFetch", self.audit)
        receipts = [row for row in events if row.get("event_type") == "data_plane.credential_lease.issued"
            and all(row.get("event", {}).get(key) == value for key, value in {
                "purpose": "dispatchSecret", "principal_id": application["principal_id"],
                "route_id": rule["route_id"], "credential_id": credential["id"],
                "policy_hash": self.policy_hash, "data_plane_binary_digest": self.args.expected_binary_sha256,
            }.items())]
        now, monotonic = time.time_ns() // 1_000_000, time.monotonic_ns()
        expiry = health.get("credential_lease_earliest_expiry_epoch_ms")
        lease_count = health.get("credential_leases")
        hot_scopes = health.get("credential_generation_hot_scopes", 0)
        conditions = {"health_expiry_integer": type(expiry) is int,
            "health_remaining_gt_1000ms": type(expiry) is int and expiry > now + WARM_MIN_REMAINING_MS,
            "health_policy_hash_matches": health.get("policy_hash") == self.policy_hash,
            "health_lease_count_integer": type(lease_count) is int,
            "health_lease_count_at_least_minimum": type(lease_count) is int and lease_count >= minimum_scopes,
            "health_hot_scope_count_at_least_minimum": type(hot_scopes) is int and hot_scopes >= minimum_scopes}
        observation.update({"comparison": {"epochMs": now, "monotonicNs": monotonic},
            "healthEarliestExpiryEpochMs": _warm_integer(expiry),
            "healthRemainingMsAtComparison": expiry - now if _warm_integer(expiry) is not None else None,
            "healthAgeAtComparisonMonotonicNs": monotonic - observation["healthFetch"]["finished"]["monotonicNs"],
            "credentialLeases": _warm_integer(lease_count), "hotScopes": _warm_integer(hot_scopes),
            "auditRowCount": len(events), "matchingScopedReceiptCount": len(receipts), "conditions": conditions})
        failed = [name for name, passed in conditions.items() if not passed]
        if failed:
            observation["failedConjuncts"] = failed
            observation["completed"] = True
            require(False, "live credential lease freshness window unavailable: " + ",".join(failed))
        valid = [row for row in receipts if type(row["event"].get("issued_at_epoch_ms")) is int
            and type(row["event"].get("expires_at_epoch_ms")) is int
            and row["event"]["issued_at_epoch_ms"] <= now
            and row["event"]["expires_at_epoch_ms"] > now + WARM_MIN_REMAINING_MS]
        typed = [row for row in receipts if type(row["event"].get("issued_at_epoch_ms")) is int
            and type(row["event"].get("expires_at_epoch_ms")) is int]
        issued = [row for row in typed if row["event"]["issued_at_epoch_ms"] <= now]
        receipt_conditions = {"scoped_dispatch_receipt_present": bool(receipts),
            "scoped_receipt_timestamps_integer": bool(typed),
            "scoped_receipt_issued_not_future": bool(issued),
            "scoped_receipt_remaining_gt_1000ms": bool(valid)}
        conditions.update(receipt_conditions)
        observation.update({"typedScopedReceiptCount": len(typed), "issuedScopedReceiptCount": len(issued),
            "warmScopedReceiptCount": len(valid)})
        if not valid:
            failed = [name for name, passed in receipt_conditions.items() if not passed]
            observation["failedConjuncts"] = failed
            observation["completed"] = True
            require(False, "app-scoped live dispatch lease receipt unavailable: " + ",".join(failed))
        receipt = max(valid, key=lambda row: row["event"]["expires_at_epoch_ms"])
        scoped_expiry = receipt["event"]["expires_at_epoch_ms"]
        observation.update({"completed": True, "scopedLeaseAuditEventId": safe_id(receipt.get("id")),
            "scopedLeaseIssuedAtEpochMs": _warm_integer(receipt["event"]["issued_at_epoch_ms"]),
            "scopedLeaseExpiryEpochMs": _warm_integer(scoped_expiry),
            "scopedLeaseRemainingMsAtComparison": scoped_expiry - now if _warm_integer(scoped_expiry) is not None else None,
            "denialDeadlineEpochMs": _warm_integer(min(expiry, scoped_expiry))})
        return {"stage": stage, "principalId": application["principal_id"], "routeId": rule["route_id"],
            "policyHash": self.policy_hash, "capturedAtEpochMs": now, "_captured_monotonic_ns": monotonic,
            "healthEarliestUnexpiredLeaseEpochMs": expiry, "scopedLeaseIssuedAtEpochMs": receipt["event"]["issued_at_epoch_ms"],
            "scopedLeaseExpiryEpochMs": scoped_expiry, "scopedLeaseAuditEventId": receipt["id"],
            "denialDeadlineEpochMs": min(expiry, scoped_expiry),
            "credentialLeases": health["credential_leases"], "hotScopes": health["credential_generation_hot_scopes"]}

    def warm_lease_evidence(self):
        """Retain partial failure-time observations without any response body."""
        value = {"warmLeaseChecks": getattr(self, "warm_lease_checks", []),
            "warmDenialChecks": getattr(self, "warm_denial_checks", [])}
        require(len(value["warmLeaseChecks"]) <= 2 and len(value["warmDenialChecks"]) <= 2,
                "warm lease evidence count exceeds bound")
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")
        require(len(encoded) <= 16384, "warm lease evidence exceeds bound")
        self.clean(encoded)
        return value

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
        revoke_before = self.warm_cas_snapshot()
        revoke_warm = self.observe_live_lease("before_app1_revoke", applications[0], rules[0], credential, minimum_scopes=2)
        self.results.append("one_shared_credential_two_apps_two_rules_both_200_with_warm_leases")
        revoked_app, _, revoked = self.submit_mutation(revoke_before, "/applications/revoke", {"id": applications[0]["id"]},
            result_key="application", authority_changed=True)
        require(revoked.get("affected_rule_ids") == [rules[0]["id"]]
                and revoked_app.get("status") == "revoked"
                and revoked_app["version"] == self.resource(revoke_before, "applications", applications[0]["id"])["version"] + 1,
                "application revoke affected sibling rules or target version differs")
        self.wait_health_loaded(revoked["policy"]["policy_hash"])
        self.denied_without_dispatch(tokens[0], warm=revoke_warm)
        snapshot, _ = self.wait_catalog_loaded("app1_revoked", expected_mutation=revoked)
        require(self.resource(snapshot, "applications", applications[0]["id"])["status"] == "revoked"
                and self.resource(snapshot, "access_rules", rules[0]["id"])["enforcement"] == "revoked"
                and self.resource(snapshot, "access_rules", rules[1]["id"])["enforcement"] == "active",
                "per-application revocation state differs")
        retained = self.resource(snapshot, "credentials", credential["id"])
        require(retained["status"] == "active" and retained["version"] == credential["version"]
                and retained["active_rule_count"] == 1, "revocation changed the shared credential")
        self.finalize_mutation(revoked, snapshot, collection="applications", result_key="application",
            event="operator_catalog.application.revoked")
        self.injected(tokens[1], applications[1], rules[1])
        self.results.append("warm_app1_revoked_403_no_dispatch_while_app2_still_200")
        rotate_before = self.warm_cas_snapshot()
        rotate_warm = self.observe_live_lease("before_app2_rotate", applications[1], rules[1], credential, minimum_scopes=1)
        rotated, replacement, rotation = self.submit_mutation(rotate_before, "/applications/rotate-token",
            {"id": applications[1]["id"], "token_lifetime_seconds": 3600}, result_key="application",
            token=True, authority_changed=True)
        require(rotated.get("token_generation") == 2 and rotated.get("principal_id") == applications[1]["principal_id"]
                and rotated["version"] == self.resource(rotate_before, "applications", applications[1]["id"])["version"] + 1,
                "rotation changed identity or failed to advance token generation")
        self.wait_health_loaded(rotation["policy"]["policy_hash"])
        self.denied_without_dispatch(tokens[1], warm=rotate_warm)
        snapshot, _ = self.wait_catalog_loaded("app2_rotated", expected_mutation=rotation)
        # Persistence checks precede both a completed mutation record and any
        # authorized request using the new token. No lost-response POST retry.
        retained = self.resource(snapshot, "credentials", credential["id"])
        persisted_app = self.resource(snapshot, "applications", applications[1]["id"])
        require(persisted_app["status"] == "active" and persisted_app.get("token_status") == "valid"
                and persisted_app.get("access_status") == "active"
                and persisted_app.get("principal_id") == rotated["principal_id"]
                and persisted_app.get("token_generation") == rotated["token_generation"]
                and self.resource(snapshot, "access_rules", rules[0]["id"])["enforcement"] == "revoked"
                and self.resource(snapshot, "access_rules", rules[1]["id"])["enforcement"] == "active",
                "rotated application persistence or sibling activation differs")
        require(len(snapshot["credentials"]) == 1 and retained["status"] == "active"
                and retained["version"] == credential["version"] and retained["active_rule_count"] == 1
                and len(snapshot["applications"]) == 2 and len(snapshot["access_rules"]) == 2,
                "shared credential or resource retention differs")
        self.finalize_mutation(rotation, snapshot, collection="applications", result_key="application",
            event="operator_catalog.application.token_rotated")
        self.denied_without_dispatch(tokens[0])
        self.injected(replacement, applications[1], rules[1])
        require(self.count() == 6, "shared credential, resource retention, or total dispatch count differs")
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
            **features.safe_evidence(self), **self.warm_lease_evidence(),
            "upstreamDispatches": 9, "responsesReleased": 7, "responsesBlocked": 2,
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
            try:
                evidence.update(check.warm_lease_evidence())
            except Exception:
                evidence["warmLeaseEvidenceUnavailable"] = True
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
