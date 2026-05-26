#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)

        from serverware import app as app_module
        from serverware import db, policy_bundle
        from serverware.auth import AdminIdentity

        db.init_db()
        snapshot = policy_bundle.write_policy_bundle(policy_bundle.demo_policy_bundle("cred-demo-bearer"))
        db.upsert_route_with_id(
            "demo.npm.publish.jit",
            {
                "name": "Demo NPM publish JIT",
                "enabled": True,
                "match_host": "registry.npmjs.org",
                "match_path_prefix": "/",
                "credential_id": None,
                "injection": {"type": "bearer"},
                "policies": [{"type": "approval", "scope": "request_digest"}],
            },
        )
        reason = "package integrity mismatch after review"
        approval = db.ensure_jit_approval_request(
            route_id="demo.npm.publish.jit",
            method="PUT",
            url="https://registry.npmjs.org/@scope%2fpkg",
            principal_id="agent:demo",
            credential_id="cred-demo-bearer",
            credential_version=1,
            policy_hash=snapshot.hash,
            request_digest="sha256:" + "a" * 64,
            operation_digest="sha256:" + "b" * 64,
            canonical_request={
                "principal": "agent:demo",
                "route_id": "demo.npm.publish.jit",
                "credential_ref": "cred-demo-bearer",
                "credential_version": "1",
                "policy_hash": snapshot.hash,
            },
            redacted_display={"package": "@scope/pkg", "version": "1.2.3"},
            pending_ttl_seconds=300,
            grant_ttl_seconds=30,
            grant_max_uses=1,
        )
        approver = AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header")
        denied = app_module.deny(
            approval["id"],
            payload=app_module.ApprovalDeny(reason=reason),
            identity=approver,
        )
        if denied["status"] != "denied" or denied["decision_note"] != reason:
            raise AssertionError(f"denial reason was not stored on the approval: {denied}")
        audit = next(item for item in db.list_audit_events(limit=20) if item["event_type"] == "approval.denied")
        if audit["event"].get("note") != reason:
            raise AssertionError(f"denial reason missing from audit event: {audit}")
        search = db.search_audit_events(approval_id=approval["id"], q=reason)
        if search["count"] != 1 or search["items"][0]["event_type"] != "approval.denied":
            raise AssertionError(f"denial audit event is not searchable by reason: {search}")

    print(json.dumps({"approval_denial_reason": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
