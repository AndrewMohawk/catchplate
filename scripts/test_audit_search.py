#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def expect_ids(label: str, result: dict, expected: set[str]) -> None:
    found = {item["event"]["marker"] for item in result["items"]}
    if found != expected:
        raise AssertionError(f"{label} returned {found}, expected {expected}: {result}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        for store in ("METADATA", "GRANT", "AUDIT"):
            os.environ[f"CATCHPLATE_{store}_STORE_BACKEND"] = "sqlite"
            os.environ.pop(f"CATCHPLATE_{store}_STORE_POSTGRES_DSN", None)
        os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
        from catchplate import db

        db.init_db()
        db.record_audit_event(
            "proxy.request_decision",
            {
                "marker": "alpha-allow",
                "principal_id": "agent:alpha",
                "route_id": "route:read",
                "policy_hash": "sha256:" + "a" * 64,
                "credential_id": "cred:alpha",
                "credential_version": 7,
                "decision": "allow",
                "attestation": {"runtime_manifest_digest": "sha256:" + "1" * 64},
            },
            actor_type="proxy",
            actor_id="route:read",
        )
        db.record_audit_event(
            "approval.approved",
            {
                "marker": "alpha-approval",
                "principalId": "agent:alpha",
                "routeId": "route:publish",
                "policyHash": "sha256:" + "b" * 64,
                "credentialRef": "cred:alpha",
                "credentialVersion": 8,
                "approval_request_id": "approval:one",
                "status": "approved",
            },
            actor_type="admin",
            actor_id="user:approver",
        )
        db.record_audit_event(
            "proxy.request_decision",
            {
                "marker": "beta-deny",
                "principal_id": "agent:beta",
                "route_id": "route:write",
                "policy_hash": "sha256:" + "c" * 64,
                "credential_id": "cred:beta",
                "credential_version": 1,
                "action": "deny",
                "module_id": "nitro-module-prod",
            },
            actor_type="proxy",
            actor_id="route:write",
        )

        expect_ids(
            "principal search",
            db.search_audit_events(principal_id="agent:alpha"),
            {"alpha-allow", "alpha-approval"},
        )
        expect_ids(
            "route and decision search",
            db.search_audit_events(route_id="route:write", decision="deny"),
            {"beta-deny"},
        )
        expect_ids(
            "policy and credential version search",
            db.search_audit_events(policy_hash="sha256:" + "a" * 64, credential_version=7),
            {"alpha-allow"},
        )
        expect_ids(
            "approval search",
            db.search_audit_events(approval_id="approval:one"),
            {"alpha-approval"},
        )
        expect_ids(
            "attestation measurement search",
            db.search_audit_events(attestation_measurement="nitro-module-prod"),
            {"beta-deny"},
        )
        expect_ids(
            "event type and actor search",
            db.search_audit_events(event_type="proxy.request_decision", actor_type="proxy", actor_id="route:read"),
            {"alpha-allow"},
        )
        expect_ids(
            "raw query search",
            db.search_audit_events(q="cred:beta"),
            {"beta-deny"},
        )

        future = db.search_audit_events(start="2999-01-01T00:00:00+00:00")
        if future["items"]:
            raise AssertionError(f"future time-window search should be empty: {future}")
        bounded = db.search_audit_events(limit=1, scan_limit=1, principal_id="agent:alpha")
        if bounded["complete"] is True or bounded["scanned"] != 1:
            raise AssertionError(f"bounded audit search did not report incomplete scan: {bounded}")

    print(json.dumps({"audit_search": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
