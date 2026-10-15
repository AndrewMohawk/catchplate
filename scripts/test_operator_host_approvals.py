#!/usr/bin/env python3
"""Focused real encrypted SQLite/signed-policy host approval transaction tests.

Uses the existing isolated catalog worker. No native authority, provider or live
database is exercised. Only the gate health observation is a fixture double.
"""
from contextlib import closing
from copy import deepcopy
import asyncio
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_catalog_github as fixture

ROOT = Path(__file__).resolve().parents[1]


def worker():
    from serverware import operator_host_approvals as store
    from serverware import operator_catalog_approvals as catalog_approvals
    f = fixture.Fixture()
    actor = f.config.ADMIN_USER_ID
    credential, application = f.credential()["credential"], f.application()
    result = f.rule(application, credential)
    with patch.object(catalog_approvals, "require_available", return_value=None):
        f.call(f.mutations.set_rule_approval, f.inputs.RuleApprovalInput(**f.review(),
            id=result["access_rule"]["id"], approval_mode="host_review_v1"), actor)
    route = f.bundles.get_policy_snapshot().routes[0]
    now = store._clock()
    assert store.enabled()

    def wire(index=1, *, accept="application/json"):
        original = {"v": 3, "principal": application["principal_id"], "client_ip": "127.0.0.1",
            "route_id": route.id, "credential_ref": credential["id"], "credential_version": "1",
            "policy_hash": f.store.get_policy_high_water()["policy_hash"],
            "request": {"method": "GET", "scheme": "https", "authority": "api.github.com",
                "path": "/repos/serverware-fixture/operator-demo/issues", "query": [],
                "headers": {"accept": accept, "authorization": "secret-placeholder-canary"},
                "body_sha256": store.digest({}), "discard_headers": [],
                "query_mode": "githubRestV1", "query_wire": None}, "operation": {}}
        return {"apiVersion": store.REQUEST_VERSION, "principalId": original["principal"],
            "routeId": route.id, "credentialId": credential["id"], "credentialVersion": 1,
            "policyHash": original["policy_hash"], "requestDigest": store.digest(original),
            "operationDigest": store.digest({k: v for k, v in original.items() if k not in {"v", "client_ip"}}),
            "attemptId": "sha256:" + format(index, "064x"), "canonicalRequest": original}

    def decide(identifier, decision="approve"):
        review = store.review(identifier, actor)
        assert review["document"]["headers"]["authorization"] == "[redacted]"
        value = {"decision": decision, "review_receipt_id": review["review_receipt_id"],
            "review_digest": review["review_digest"], "note": None}
        return store.decide(identifier, actor, value), value

    check = unittest.TestCase()
    first = store.claim(wire())
    assert first["status"] == "pending"
    identifier = first["approvalId"]
    assert store.list_pending(actor)[0]["id"] == identifier
    with check.assertRaises(store.ApprovalConflict):
        store.review(identifier, "different-reviewer")
    with check.assertRaises(store.ApprovalConflict):
        store.decide(identifier, actor, {"decision": "approve", "review_receipt_id": identifier,
            "review_digest": "sha256:" + "0" * 64, "note": None})
    approved, decision = decide(identifier)
    assert approved["status"] == "approved"
    with check.assertRaises(store.ApprovalConflict):
        store.decide(identifier, actor, decision)
    assert store.claim(wire(2))["status"] == "claimed"
    assert store.claim(wire(2))["status"] == "consumed"
    assert store.status(identifier, actor)["status"] == "consumed"
    renewed = store.claim(wire(3))
    assert renewed["status"] == "pending" and renewed["approvalId"] != identifier
    rejected = store.claim(wire(4, accept="application/vnd.github+json"))
    decide(rejected["approvalId"], "deny")
    assert store.claim(wire(5, accept="application/vnd.github+json"))["status"] == "denied"
    with patch.object(store, "_clock", return_value=now + 301_000):
        expired = store.claim(wire(6, accept="application/vnd.github+json"))
    assert expired["status"] == "pending" and expired["approvalId"] != rejected["approvalId"]

    # Digest tampering and revoked/current credential changes cannot claim.
    forged = wire(7)
    forged["canonicalRequest"]["request"]["path"] += "/1"
    with check.assertRaises(store.ApprovalConflict):
        store.claim(forged)
    with closing(f.db.connect()) as conn, conn:
        conn.execute("UPDATE credentials SET credential_version=2 WHERE id=?", (credential["id"],))
    with check.assertRaises(store.ApprovalConflict):
        store.claim(wire(8))
    with closing(f.db.connect()) as conn, conn:
        conn.execute("UPDATE credentials SET credential_version=1 WHERE id=?", (credential["id"],))

    # A failed audit rolls back the actual decision, receipt use and grant.
    receipt = store.review(renewed["approvalId"], actor)
    value = {"decision": "approve", "review_receipt_id": receipt["review_receipt_id"],
        "review_digest": receipt["review_digest"], "note": None}
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER host_approval_abort BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT,'synthetic audit refusal'); END")
    try:
        with check.assertRaises(sqlite3.IntegrityError):
            store.decide(renewed["approvalId"], actor, value)
    finally:
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TRIGGER host_approval_abort")
    assert store.status(renewed["approvalId"], actor)["status"] == "pending"
    assert store.decide(renewed["approvalId"], actor, value)["status"] == "approved"
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER host_claim_abort BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT,'synthetic audit refusal'); END")
    try:
        with check.assertRaises(sqlite3.IntegrityError):
            store.claim(wire(9))
    finally:
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TRIGGER host_claim_abort")
    assert store.status(renewed["approvalId"], actor)["status"] == "approved"
    assert store.claim(wire(10))["status"] == "claimed"
    rows = fixture.workspace.rows(f.db, "approval_requests")
    assert all(row["url"].startswith("sha256:") and row["canonical_request"].startswith("v2:") for row in rows)
    assert "secret-placeholder-canary" not in json.dumps(rows)
    events = fixture.workspace.rows(f.db, "audit_events")
    assert "secret-placeholder-canary" not in json.dumps(events)
    assert sum(e["event_type"] == "operator.host_approval.claimed" for e in events) == 2
    assert not fixture.workspace.rows(f.db, "approval_request_decisions")

    async def transport():
        from fastapi import FastAPI
        from serverware import operator_host_approvals_api as api
        small = FastAPI()
        small.include_router(api.router)

        async def request(path, *, token=True, origin=True, body=b"{}", machine=False):
            headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
            if token:
                headers.append((b"x-serverware-data-plane-token" if machine else b"x-serverware-admin-token",
                    (f.config.DATA_PLANE_CREDENTIAL_LEASE_TOKEN if machine else f.config.ADMIN_TOKEN).encode()))
            if origin:
                headers.append((b"origin", f.config.PUBLIC_URL.rstrip("/").encode()))
            scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"",
                "root_path": "", "headers": headers, "client": ("127.0.0.1", 1234), "server": ("test", 443)}
            received, sent = [], []
            async def receive():
                received.append(True)
                return {"type": "http.request", "body": body, "more_body": False}
            async def send(message):
                sent.append(message)
            await small(scope, receive, send)
            code = next(v["status"] for v in sent if v["type"] == "http.response.start")
            return code, received

        path = store.PREFIX + "/" + identifier + "/review"
        assert await request(path, token=False) == (401, [])
        assert await request(path, origin=False) == (403, [])
        assert await request(store.CLAIM_PATH, token=False, machine=True) == (401, [])
        with patch.object(store, "available", return_value=True):
            assert (await request(path, body=b'{"duplicate":1,"duplicate":2}'))[0] == 422
            assert (await request(store.CLAIM_PATH, machine=True, body=store.canonical(wire(11)).encode()))[0] == 200
        assert api.owns_post(path) and not api.owns_post(path + "/extra")

    asyncio.run(transport())
    return {"exact_one_use_new_pending": True, "review_and_currentness": True,
        "encrypted_storage_real_audit": True, "decision_and_claim_rollback": True, "authenticated_transport": True}


class HostApprovalTests(unittest.TestCase):
    def setUp(self):
        fixture.OperatorCatalogGithubTests.setUp(self)
        self.environment.update(SERVERWARE_HOST_TRUSTED_APPROVALS_ENABLED="1",
            SERVERWARE_ADMIN_TOKEN="synthetic-host-approval-admin-token",
            SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN="synthetic-host-approval-service-token",
            SERVERWARE_DATA_PLANE_INSTANCE_ID="synthetic-host-approval-gate")

    def test_actual_encrypted_signed_current_transaction_and_authenticated_transport(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, fixture.worker_failure_summary(result))
        self.assertEqual(len(json.loads(result.stdout)), 5)
        self.assertTrue(all(json.loads(result.stdout).values()))


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        os.umask(0o077)
        try:
            outcome = worker()
        except Exception as error:
            print(json.dumps(fixture.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)
