#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def sign_break_glass_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    digest = app_module._break_glass_payload_digest(payload)
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="break_glass.grant",
        resource_id=payload.route_id,
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if payload.reason not in serialized_options:
        return webauthn.dev_assertion(options["publicKey"]["challenge"])
    raise AssertionError("break-glass WebAuthn challenge leaked the human reason")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        policy_bundle.write_policy_bundle(policy_bundle.demo_policy_bundle("cred-demo-bearer"))
        snapshot = policy_bundle.get_policy_snapshot()
        if snapshot is None:
            raise AssertionError("demo policy did not load")

        user_id = "user:incident-commander"
        identity = AdminIdentity(user_id, frozenset({"approver"}), "admin-token-header")
        webauthn.create_dev_credential(user_id)
        run_id = uuid.uuid4().hex
        request_digest = "sha256:" + hashlib.sha256(f"break-glass-request:{run_id}".encode()).hexdigest()
        operation_digest = "sha256:" + hashlib.sha256(f"break-glass-operation:{run_id}".encode()).hexdigest()
        payload = app_module.BreakGlassGrantRequest(
            principalId="agent:demo",
            routeId="demo.echo",
            credentialId="cred-demo-bearer",
            credentialVersion=1,
            policyHash=snapshot.hash,
            requestDigest=request_digest,
            operationDigest=operation_digest,
            method="GET",
            url="https://demo-upstream:8443/echo",
            grantTtlSeconds=120,
            grantMaxUses=1,
            reason="incident response access",
            canonicalRequest={"path": "/echo"},
            redactedDisplay={"summary": "incident response probe"},
        )
        payload.mfa = {"assertion": sign_break_glass_assertion(app_module, webauthn, payload, user_id)}
        granted = app_module.break_glass_grant(payload, identity=identity)
        if granted.get("ok") is not True or not granted.get("approvalId"):
            raise AssertionError(f"break-glass grant failed: {granted}")

        audits = db.list_audit_events(limit=50)
        event_types = [item["event_type"] for item in audits]
        if "approval.break_glass_granted" not in event_types or "approval.approved" not in event_types:
            raise AssertionError(f"break-glass grant did not write approval audit events: {event_types}")
        break_event = next(item for item in audits if item["event_type"] == "approval.break_glass_granted")
        if break_event["event"].get("reason") != payload.reason:
            raise AssertionError(f"break-glass audit did not preserve reason: {break_event}")
        if break_event["event"].get("control_plane_mfa", {}).get("method") != "webauthn":
            raise AssertionError(f"break-glass audit did not include WebAuthn evidence: {break_event}")

        grant_lookup = dict(
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            credential_id=payload.credential_id,
            credential_version=payload.credential_version,
            policy_hash=payload.policy_hash,
            request_digest=payload.request_digest,
            operation_digest=payload.operation_digest,
        )
        available = db.find_jit_grant_result(**grant_lookup)
        still_available = db.find_jit_grant_result(**grant_lookup)
        if available.get("available") is not True or still_available.get("available") is not True:
            raise AssertionError(f"non-consuming grant availability check changed the grant: {available} {still_available}")

        consumed = db.consume_jit_grant_result(
            **grant_lookup,
            flow_id=f"break-glass-flow-1:{run_id}",
        )
        if consumed.get("consumed") is not True:
            raise AssertionError(f"break-glass grant was not consumable through JIT machinery: {consumed}")
        reused = db.consume_jit_grant_result(
            **grant_lookup,
            flow_id=f"break-glass-flow-2:{run_id}",
        )
        if reused.get("consumed") is True:
            raise AssertionError(f"one-use break-glass grant was reusable: {reused}")

    print(json.dumps({"break_glass_grants": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
