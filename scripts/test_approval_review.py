#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def make_approval(db, snapshot, *, digest_suffix: str, redacted_display: dict, canonical_request: dict):
    return db.ensure_jit_approval_request(
        route_id="demo.npm.publish.jit",
        method="PUT",
        url="https://registry.npmjs.org/@scope%2fpkg",
        principal_id="agent:demo",
        credential_id="cred-demo-bearer",
        credential_version=2,
        policy_hash=snapshot.hash,
        request_digest="sha256:" + digest_suffix * 64,
        operation_digest="sha256:" + digest_suffix.upper() * 64,
        canonical_request=canonical_request,
        redacted_display=redacted_display,
        pending_ttl_seconds=300,
        grant_ttl_seconds=30,
        grant_max_uses=1,
    )


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
        previous = make_approval(
            db,
            snapshot,
            digest_suffix="c",
            redacted_display={"package": "@scope/pkg", "version": "1.2.2"},
            canonical_request={"principal": "agent:demo", "operation": {"packageName": "@scope/pkg", "packageVersion": "1.2.2"}},
        )
        db.deny_request(previous["id"], note="prior package failed review", actor_id="user:demo")

        current = make_approval(
            db,
            snapshot,
            digest_suffix="d",
            redacted_display={
                "package": "@scope/pkg",
                "version": "1.2.3",
                "secretToken": "top-secret-value",
            },
            canonical_request={
                "principal": "agent:demo",
                "client_ip": "10.20.0.8",
                "proxy_authorization_hash": "sha256:" + "9" * 64,
                "request": {
                    "method": "PUT",
                    "body_sha256": "sha256:" + "4" * 64,
                    "headers": {"authorization": "Bearer top-secret-value"},
                },
                "operation": {
                    "type": "npm.publish",
                    "packageName": "@scope/pkg",
                    "packageVersion": "1.2.3",
                    "tarballIntegrity": "sha512-demo",
                    "authorization": "Bearer top-secret-value",
                },
            },
        )
        review = app_module.approval_review(
            current["id"],
            _=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
        )
        if review["principal_id"] != "agent:demo" or review["route_id"] != "demo.npm.publish.jit":
            raise AssertionError(f"approval review missing principal/route context: {review}")
        if review["source_identity"].get("client_ip") != "10.20.0.8":
            raise AssertionError(f"approval review missing source identity: {review}")
        if review["body_hash"] != "sha256:" + "4" * 64:
            raise AssertionError(f"approval review missing body hash: {review}")
        if review["normalized_operation_fields"].get("packageName") != "@scope/pkg":
            raise AssertionError(f"approval review missing operation fields: {review}")
        if review["normalized_operation_fields"].get("authorization") != "[redacted]":
            raise AssertionError(f"approval review did not redact sensitive operation fields: {review}")
        if review["redacted_payload_summary"].get("secretToken") != "[redacted]":
            raise AssertionError(f"approval review did not redact sensitive display fields: {review}")
        if "prior package failed review" not in json.dumps(review["previous_similar_approvals"], sort_keys=True):
            raise AssertionError(f"approval review missing previous similar approvals: {review}")
        if review["retry_semantics"].get("agent_receives_secret_or_token") is not False:
            raise AssertionError(f"approval review retry semantics are unsafe: {review}")
        for expected_flag in ("credential_version_bound", "policy_hash_current", "webauthn_required", "one_use_grant"):
            if expected_flag not in review["risk_flags"]:
                raise AssertionError(f"approval review missing risk flag {expected_flag}: {review}")
        if "top-secret-value" in json.dumps(review, sort_keys=True):
            raise AssertionError(f"approval review leaked a secret value: {review}")

        changed_bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
        changed_bundle["metadata"]["sequence"] = 2
        policy_bundle.write_policy_bundle(changed_bundle)
        stale_review = app_module.approval_review(
            current["id"],
            _=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
        )
        if "policy_hash_not_current" not in stale_review["risk_flags"]:
            raise AssertionError(f"stale approval review did not flag policy change: {stale_review}")
        try:
            app_module.approve(
                current["id"],
                ttl_seconds=30,
                payload=None,
                identity=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 409 or "policy changed" not in str(exc.detail):
                raise AssertionError(f"stale approval failed with the wrong error: {exc.detail}") from exc
        else:
            raise AssertionError("stale approval was accepted after the active policy changed")

    print(json.dumps({"approval_review": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
