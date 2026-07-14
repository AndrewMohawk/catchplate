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


def dry_run_case(app_module: Any) -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect="allow",
    )


def sign_publish_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    digest = app_module._policy_publish_payload_digest(payload)
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=payload.bundle["metadata"]["id"],
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "demo-token-from-vault" in serialized_options:
        raise AssertionError("policy canary WebAuthn challenge leaked credential material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def sign_activate_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str, policy_id: str) -> dict[str, Any]:
    digest = app_module._policy_canary_activate_payload_digest(payload)
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> dict[str, Any]:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
    raise AssertionError(f"{label} unexpectedly succeeded")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_CANARY_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:publisher"
        identity = AdminIdentity(user_id, frozenset({"policy_publisher", "policy_author", "auditor"}), "admin-token-header")
        webauthn.create_dev_credential(user_id)
        initial = policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))
        policy_bundle.enforce_policy_high_water(initial)
        active_before = policy_bundle.get_policy_snapshot()

        full_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "direct full publish while canary is required",
            lambda: app_module.policy_publish(full_payload, identity=identity),
            412,
            "canary activation",
        )

        empty_status = app_module.policy_canary_status(_=identity)
        if empty_status != {"ok": True, "canary": None, "monitoring": None}:
            raise AssertionError(f"empty canary status was not idempotent: {empty_status}")

        canary_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        try:
            app_module.PolicyPublishRequest(
                bundle=candidate_bundle(policy_bundle, 2),
                dryRun=[dry_run_case(app_module)],
                activationMode="canary",
                canaryPercent=10.0,
            )
        except Exception as exc:
            if type(exc).__name__ != "ValidationError":
                raise
        else:
            raise AssertionError("removed canary traffic percentage was still accepted")
        canary_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, canary_payload, user_id)}
        canary = app_module.policy_publish(canary_payload, identity=identity)
        canary_id = canary["canary"]["id"]
        candidate_hash = canary["candidate"]["policyHash"]
        if canary.get("published") is not False or canary["policyHash"] != active_before.hash:
            raise AssertionError(f"canary publish activated the policy instead of staging it: {canary}")
        if not app_module.POLICY_CANARY_BUNDLE_PATH.exists():
            raise AssertionError("canary signed bundle was not written")
        still_active = policy_bundle.get_policy_snapshot()
        if not still_active or still_active.hash != active_before.hash:
            raise AssertionError("active policy changed during canary start")

        db.record_audit_event(
            "request.completed",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 12.5,
                "policy_hash": candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        status = app_module.policy_canary_status(_=identity)
        if status["monitoring"]["auditEvents"] < 1 or status["monitoring"]["denials"] != 0:
            raise AssertionError(f"canary monitoring did not include audit evidence: {status}")
        if status["monitoring"]["latencyMsP95"] != 12.5:
            raise AssertionError(f"canary monitoring did not report latency evidence: {status}")

        activation = app_module.PolicyCanaryActivationRequest(canaryId=canary_id)
        activation.mfa = {"assertion": sign_activate_assertion(app_module, webauthn, activation, user_id, "serverware-demo")}
        activated = app_module.policy_canary_activate(activation, identity=identity)
        if activated.get("published") is not True or activated["policyHash"] != candidate_hash:
            raise AssertionError(f"canary activation did not publish the candidate: {activated}")
        active_after = policy_bundle.get_policy_snapshot()
        if not active_after or active_after.hash != candidate_hash:
            raise AssertionError("active policy snapshot was not updated after canary activation")

        audits = db.list_audit_events(limit=50)
        event_types = [item["event_type"] for item in audits]
        for expected in ("policy.canary.started", "policy.canary.activated", "policy.published"):
            if expected not in event_types:
                raise AssertionError(f"missing {expected} audit event: {event_types}")
        published_event = next(item for item in audits if item["event_type"] == "policy.published")
        if published_event["event"].get("activation_mode") != "canary":
            raise AssertionError(f"published audit event did not bind canary activation: {published_event}")

        second_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        second_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, second_payload, user_id)}
        second_canary = app_module.policy_publish(second_payload, identity=identity)
        cancel_payload = app_module.PolicyCanaryCancelRequest(canaryId=second_canary["canary"]["id"], note="superseded")
        cancelled = app_module.policy_canary_cancel(cancel_payload, identity=identity)
        if cancelled["canary"]["status"] != "cancelled":
            raise AssertionError(f"canary cancel did not update state: {cancelled}")
        cancelled_activation = app_module.PolicyCanaryActivationRequest(canaryId=second_canary["canary"]["id"])
        expect_http_error(
            "activate cancelled canary",
            lambda: app_module.policy_canary_activate(cancelled_activation, identity=identity),
            409,
            "cancelled",
        )

    print(json.dumps({"ok": True, "policy_canary_workflow": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
