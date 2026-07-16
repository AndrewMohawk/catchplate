#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def parse_jsonl(payload: str) -> list[dict]:
    return [json.loads(line) for line in payload.splitlines() if line.strip()]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"

        from serverware import app as app_module
        from serverware import db
        from serverware.auth import AdminIdentity

        db.init_db()
        db.record_audit_event(
            "proxy.request_decision",
            {
                "marker": "export-alpha-allow",
                "principal_id": "agent:alpha",
                "route_id": "route:read",
                "policy_hash": "sha256:" + "a" * 64,
                "credential_id": "cred:alpha",
                "credential_version": 3,
                "decision": "allow",
                "attestation": {"runtime_manifest_digest": "sha256:" + "1" * 64},
            },
            actor_type="proxy",
            actor_id="route:read",
        )
        db.record_audit_event(
            "proxy.request_decision",
            {
                "marker": "export-alpha-deny",
                "principal_id": "agent:alpha",
                "route_id": "route:write",
                "policy_hash": "sha256:" + "b" * 64,
                "credential_id": "cred:alpha",
                "credential_version": 4,
                "decision": "deny",
                "approval_request_id": "approval:export-one",
            },
            actor_type="proxy",
            actor_id="route:write",
        )
        db.record_audit_event(
            "key_release.verified",
            {
                "marker": "export-beta-attestation",
                "principal_id": "agent:beta",
                "route_id": "route:key",
                "policy_hash": "sha256:" + "c" * 64,
                "credential_id": "cred:beta",
                "credential_version": 1,
                "module_id": "nitro-module-export",
            },
            actor_type="admin",
            actor_id="user:operator",
        )

        direct = parse_jsonl(db.export_audit_events_jsonl(principal_id="agent:alpha", decision="deny"))
        if [item["kind"] for item in direct] != [
            "serverware.auditExport.v1",
            "serverware.auditEvent.v1",
            "serverware.auditExportEnd.v1",
        ]:
            raise AssertionError(f"audit export kinds are wrong: {direct}")
        header, event_line, footer = direct
        if header["count"] != 1 or header["complete"] is not True:
            raise AssertionError(f"audit export header has wrong counts: {header}")
        if header["chain"].get("ok") is not True or not header["chain"].get("head"):
            raise AssertionError(f"audit export did not include verified chain metadata: {header}")
        exported_event = event_line["event"]
        if exported_event["event"]["marker"] != "export-alpha-deny":
            raise AssertionError(f"audit export returned the wrong event: {event_line}")
        for field in ("event_hash", "prev_event_hash", "created_at"):
            if field not in exported_event:
                raise AssertionError(f"audit export event is missing chain field {field}: {exported_event}")
        if footer["chain_head"] != header["chain"]["head"]:
            raise AssertionError(f"audit export footer did not bind the chain head: {footer}")

        bounded = parse_jsonl(db.export_audit_events_jsonl(principal_id="agent:alpha", limit=1, scan_limit=1))
        if bounded[0]["complete"] is True or bounded[-1]["complete"] is True:
            raise AssertionError(f"bounded audit export did not report incomplete scan: {bounded}")

        response = app_module.audit_export(
            limit=1000,
            scan_limit=50000,
            event_type=None,
            actor_type=None,
            actor_id=None,
            principal_id="agent:beta",
            route_id=None,
            policy_hash=None,
            credential_id=None,
            credential_version=None,
            approval_id=None,
            decision=None,
            attestation_measurement="nitro-module-export",
            start=None,
            end=None,
            q=None,
            _=AdminIdentity("user:auditor", frozenset({"auditor"}), "admin-token-header"),
        )
        if response.media_type != "application/x-ndjson":
            raise AssertionError(f"audit export endpoint returned wrong media type: {response.media_type}")
        api_lines = parse_jsonl(response.body.decode("utf-8"))
        if api_lines[1]["event"]["event"]["marker"] != "export-beta-attestation":
            raise AssertionError(f"audit export endpoint did not apply filters: {api_lines}")

    print(json.dumps({"audit_export": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
