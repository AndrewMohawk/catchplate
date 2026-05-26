#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def candidate_bundle(policy_bundle: Any, sequence: int) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
    bundle["metadata"]["sequence"] = sequence
    return bundle


def dry_run_case(app_module: Any, *, expect: str = "allow") -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect=expect,
    )


def sign_publish_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    digest = app_module._policy_publish_payload_digest(payload)
    policy_id = payload.bundle["metadata"]["id"]
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "demo-token-from-vault" in serialized_options:
        raise AssertionError("policy publish WebAuthn challenge leaked credential material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> None:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return
    raise AssertionError(f"{label} unexpectedly succeeded")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:publisher"
        webauthn.create_dev_credential(user_id)
        identity = AdminIdentity(user_id, frozenset({"policy_publisher", "policy_author"}), "admin-token-header")
        policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))

        publish_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        publish_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, publish_payload, user_id)}
        published = app_module.policy_publish(publish_payload, identity=identity)
        if published.get("published") is not True or published["candidate"]["sequence"] != 2:
            raise AssertionError(f"policy publish returned invalid result: {published}")
        if published["dryRun"]["passed"] is not True or published["dryRun"]["count"] != 1:
            raise AssertionError(f"policy publish did not run dry-run checks: {published}")
        active = policy_bundle.get_policy_snapshot()
        if not active or active.hash != published["policyHash"]:
            raise AssertionError("active policy snapshot was not updated after publish")
        audits = db.list_audit_events(limit=20)
        policy_events = [item for item in audits if item["event_type"] == "policy.published"]
        if not policy_events:
            raise AssertionError(f"policy publish audit event missing: {audits}")
        audit_payload = policy_events[0]["event"]
        if audit_payload.get("control_plane_mfa", {}).get("method") != "webauthn":
            raise AssertionError(f"policy publish audit event missing MFA evidence: {audit_payload}")
        if audit_payload.get("dry_run", {}).get("passed") is not True:
            raise AssertionError(f"policy publish audit event missing dry-run evidence: {audit_payload}")

        stale_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        stale_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, stale_payload, user_id)}
        expect_http_error(
            "stale policy publish",
            lambda: app_module.policy_publish(stale_payload, identity=identity),
            409,
            "sequence must increase",
        )

        no_dry_run_payload = app_module.PolicyPublishRequest(bundle=candidate_bundle(policy_bundle, 3), dryRun=[])
        expect_http_error(
            "policy publish without dry-run",
            lambda: app_module.policy_publish(no_dry_run_payload, identity=identity),
            412,
            "dry-run decision tests",
        )

        failing_dry_run_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module, expect="deny")],
        )
        expect_http_error(
            "policy publish with failing dry-run",
            lambda: app_module.policy_publish(failing_dry_run_payload, identity=identity),
            409,
            "policy dry-run failed",
        )

        missing_mfa_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "policy publish without MFA",
            lambda: app_module.policy_publish(missing_mfa_payload, identity=identity),
            412,
            "WebAuthn assertion required",
        )

    print(json.dumps({"ok": True, "policy_publish_workflow": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
