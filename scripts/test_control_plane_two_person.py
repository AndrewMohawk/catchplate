#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> Any:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return exc.detail
    raise AssertionError(f"{label} unexpectedly succeeded")


def candidate_bundle(policy_bundle: Any, sequence: int) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
    bundle["metadata"]["sequence"] = sequence
    return bundle


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "0"
        os.environ["SERVERWARE_CONTROL_PLANE_TWO_PERSON_TTL_SECONDS"] = "300"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)

        from serverware import app as app_module
        from serverware import db, policy_bundle
        from serverware.auth import AdminIdentity

        db.init_db()
        requester = AdminIdentity("user:requester", frozenset({"credential_owner", "policy_publisher"}), "admin-token-header")
        credential_approver = AdminIdentity("user:credential-approver", frozenset({"credential_owner"}), "admin-token-header")
        policy_approver = AdminIdentity("user:policy-approver", frozenset({"policy_publisher"}), "admin-token-header")
        wrong_approver = AdminIdentity("user:policy-author", frozenset({"policy_author"}), "admin-token-header")

        credential_payload = app_module.CredentialCreate(
            name="Production Google OAuth",
            kind="bearer",
            secret="super-secret-token",
            metadata={"scope": "gmail.readonly"},
        )
        pending_detail = expect_http_error(
            "credential create without second approval",
            lambda: app_module.create_credential(credential_payload, identity=requester),
            428,
            "control_plane_approval_required",
        )
        approval_id = pending_detail["approvalId"]
        if db.list_credentials():
            raise AssertionError("credential mutation ran before second-person approval")
        pending = db.get_control_plane_approval(approval_id)
        serialized_pending = json.dumps(pending, sort_keys=True)
        if "super-secret-token" in serialized_pending:
            raise AssertionError("control-plane approval request stored plaintext credential material")
        if pending["payload_digest"] != pending_detail["payloadDigest"]:
            raise AssertionError(f"approval payload digest mismatch: {pending}")

        expect_http_error(
            "control-plane self approval",
            lambda: app_module.control_plane_approval_approve(approval_id, payload=None, identity=requester),
            403,
            "cannot approve their own",
        )
        expect_http_error(
            "control-plane wrong approval role",
            lambda: app_module.control_plane_approval_approve(approval_id, payload=None, identity=wrong_approver),
            403,
            "required role",
        )
        approved = app_module.control_plane_approval_approve(
            approval_id,
            payload=app_module.ControlPlaneApprovalDecision(note="credential rotation reviewed"),
            identity=credential_approver,
        )
        if approved["status"] != "approved" or approved["approved_by"] != credential_approver.user_id:
            raise AssertionError(f"credential approval was not approved: {approved}")

        credential_payload.mfa = {"approvalId": approval_id}
        created = app_module.create_credential(credential_payload, identity=requester)
        if created["name"] != credential_payload.name or "secret" in created:
            raise AssertionError(f"credential create returned unsafe payload: {created}")
        consumed = db.get_control_plane_approval(approval_id)
        if consumed["status"] != "consumed" or consumed["consumed_by"] != requester.user_id:
            raise AssertionError(f"approval was not consumed by the mutation: {consumed}")
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"credential audit outbox did not drain: {delivery}")
        credential_audit = next(item for item in db.list_audit_events(limit=20) if item["event_type"] == "credential.created")
        if credential_audit["event"].get("control_plane_approval", {}).get("approved_by") != credential_approver.user_id:
            raise AssertionError(f"credential audit missing second-person evidence: {credential_audit}")
        expect_http_error(
            "reused control-plane approval",
            lambda: app_module.create_credential(credential_payload, identity=requester),
            409,
            "approval_consumed",
        )

        policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))
        publish_payload = app_module.PolicyPublishRequest(bundle=candidate_bundle(policy_bundle, 2), dryRun=[])
        policy_pending = expect_http_error(
            "policy publish without second approval",
            lambda: app_module.policy_publish(publish_payload, identity=requester),
            428,
            "control_plane_approval_required",
        )
        policy_approval_id = policy_pending["approvalId"]
        app_module.control_plane_approval_approve(policy_approval_id, payload=None, identity=policy_approver)
        publish_payload.mfa = {"approvalId": policy_approval_id}
        published = app_module.policy_publish(publish_payload, identity=requester)
        if published.get("published") is not True or published["candidate"]["sequence"] != 2:
            raise AssertionError(f"policy publish failed after second-person approval: {published}")
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"policy audit outbox did not drain: {delivery}")
        policy_audit = next(item for item in db.list_audit_events(limit=50) if item["event_type"] == "policy.published")
        if policy_audit["event"].get("control_plane_approval", {}).get("approved_by") != policy_approver.user_id:
            raise AssertionError(f"policy audit missing second-person evidence: {policy_audit}")

        search = db.search_audit_events(event_type="control_plane.approval.consumed", approval_id=policy_approval_id)
        if search["count"] != 1:
            raise AssertionError(f"consumed approval audit is not searchable: {search}")

        original_authority_lock = db._lock_webauthn_authority

        def delayed_authority_lock(conn: Any) -> None:
            original_authority_lock(conn)
            time.sleep(0.12)

        expiring = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="expiry-before-approve",
            payload_digest="sha256:" + "a" * 64,
            requester_id=requester.user_id,
            request={"summary": "expiry lock test"},
            ttl_seconds=300,
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE control_plane_approvals SET expires_at = ? WHERE id = ?",
                ((db.utcnow() + timedelta(milliseconds=50)).isoformat(), expiring["id"]),
            )
        db._lock_webauthn_authority = delayed_authority_lock
        try:
            if db.approve_control_plane_approval(
                expiring["id"], actor_id=credential_approver.user_id
            ) is not None:
                raise AssertionError("approval crossed its expiry while waiting for the authority lock")
        finally:
            db._lock_webauthn_authority = original_authority_lock

        expiring = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="expiry-before-consume",
            payload_digest="sha256:" + "b" * 64,
            requester_id=requester.user_id,
            request={"summary": "consume expiry lock test"},
            ttl_seconds=300,
        )
        if db.approve_control_plane_approval(
            expiring["id"], actor_id=credential_approver.user_id
        ) is None:
            raise AssertionError("consume expiry fixture was not approved")
        with db.connect() as conn:
            conn.execute(
                "UPDATE control_plane_approvals SET expires_at = ? WHERE id = ?",
                ((db.utcnow() + timedelta(milliseconds=50)).isoformat(), expiring["id"]),
            )
        db._lock_webauthn_authority = delayed_authority_lock
        try:
            result = db.consume_control_plane_approval(
                expiring["id"],
                action="credential.create",
                resource_id="expiry-before-consume",
                payload_digest="sha256:" + "b" * 64,
                actor_id=requester.user_id,
            )
            if result != {"ok": False, "reason": "approval_expired"}:
                raise AssertionError(f"consumption crossed approval expiry: {result}")
        finally:
            db._lock_webauthn_authority = original_authority_lock

        original_audit_backend = db.AUDIT_STORE_BACKEND
        original_postgres_append = db._append_postgres_audit_event
        db.AUDIT_STORE_BACKEND = "postgres"
        try:
            try:
                with db.connect() as conn:
                    db.append_audit_event(
                        conn,
                        event_type="test.metadata.rollback",
                        actor_type="system",
                        actor_id=None,
                        event={"must_not_commit": True},
                    )
                    raise RuntimeError("force metadata rollback")
            except RuntimeError as exc:
                if str(exc) != "force metadata rollback":
                    raise
            status = db.metadata_audit_outbox_status()
            if status["pending"] != 0:
                raise AssertionError(f"rolled-back audit intent survived: {status}")

            with db.connect() as conn:
                staged = db.append_audit_event(
                    conn,
                    event_type="test.metadata.commit",
                    actor_type="system",
                    actor_id=None,
                    event={"committed": True},
                    idempotency_key="metadata-outbox-commit-test",
                )
            if staged.get("outbox_status") != "pending":
                raise AssertionError(f"metadata audit intent was not staged: {staged}")

            def fake_postgres_append(**kwargs: Any) -> dict[str, Any]:
                return {
                    "id": kwargs["idempotency_key"],
                    "event_hash": "sha256:" + "c" * 64,
                }

            db._append_postgres_audit_event = fake_postgres_append
            delivery = db.drain_metadata_audit_outbox(limit=10)
            if delivery != {"claimed": 1, "audited": 1, "failed": 0, "pending": 0}:
                raise AssertionError(f"metadata audit outbox delivery failed: {delivery}")
        finally:
            db._append_postgres_audit_event = original_postgres_append
            db.AUDIT_STORE_BACKEND = original_audit_backend

    print(json.dumps({"control_plane_two_person": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
