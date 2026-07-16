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
        route_approver = AdminIdentity("user:route-approver", frozenset({"policy_author"}), "admin-token-header")
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

        rollback_credential = app_module.CredentialCreate(
            name="Rollback credential",
            kind="bearer",
            secret="rollback-secret",
            metadata={"purpose": "transaction-regression"},
        )
        rollback_detail = expect_http_error(
            "credential rollback approval request",
            lambda: app_module.create_credential(rollback_credential, identity=requester),
            428,
            "control_plane_approval_required",
        )
        rollback_approval_id = rollback_detail["approvalId"]
        app_module.control_plane_approval_approve(
            rollback_approval_id, payload=None, identity=credential_approver
        )
        rollback_credential.mfa = {"approvalId": rollback_approval_id}
        original_append_audit_event = db.append_audit_event

        def reject_credential_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "credential.created":
                raise db.AuditStoreError("injected credential audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_credential_audit
        try:
            try:
                app_module.create_credential(rollback_credential, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("credential mutation committed after audit failure")
        finally:
            db.append_audit_event = original_append_audit_event
        if db.get_control_plane_approval(rollback_approval_id)["status"] != "approved":
            raise AssertionError("credential audit failure consumed its approval")
        if any(item["name"] == rollback_credential.name for item in db.list_credentials()):
            raise AssertionError("credential audit failure committed the credential")
        retried_credential = app_module.create_credential(
            rollback_credential, identity=requester
        )
        if retried_credential["name"] != rollback_credential.name:
            raise AssertionError("credential approval was not reusable after rollback")

        rollback_route = app_module.RouteCreate(
            name="Rollback route",
            match_host="rollback.example",
            match_path_prefix="/transaction",
        )
        route_detail = expect_http_error(
            "route rollback approval request",
            lambda: app_module.create_route(rollback_route, identity=requester),
            428,
            "control_plane_approval_required",
        )
        route_approval_id = route_detail["approvalId"]
        app_module.control_plane_approval_approve(
            route_approval_id, payload=None, identity=route_approver
        )
        rollback_route.mfa = {"approvalId": route_approval_id}

        def reject_route_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "route.created":
                raise db.AuditStoreError("injected route audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_route_audit
        try:
            try:
                app_module.create_route(rollback_route, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("route mutation committed after audit failure")
        finally:
            db.append_audit_event = original_append_audit_event
        if db.get_control_plane_approval(route_approval_id)["status"] != "approved":
            raise AssertionError("route audit failure consumed its approval")
        if any(item["name"] == rollback_route.name for item in db.list_routes()):
            raise AssertionError("route audit failure committed the route")
        retried_route = app_module.create_route(rollback_route, identity=requester)
        if retried_route["name"] != rollback_route.name:
            raise AssertionError("route approval was not reusable after rollback")

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

        policy_before_rollback = policy_bundle.get_policy_snapshot()
        high_water_before_rollback = db.get_policy_high_water()
        rollback_publish = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3), dryRun=[]
        )
        policy_rollback_detail = expect_http_error(
            "policy rollback approval request",
            lambda: app_module.policy_publish(rollback_publish, identity=requester),
            428,
            "control_plane_approval_required",
        )
        policy_rollback_approval_id = policy_rollback_detail["approvalId"]
        app_module.control_plane_approval_approve(
            policy_rollback_approval_id, payload=None, identity=policy_approver
        )
        rollback_publish.mfa = {"approvalId": policy_rollback_approval_id}

        def reject_policy_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "policy.published":
                raise db.AuditStoreError("injected policy audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_policy_audit
        try:
            try:
                app_module.policy_publish(rollback_publish, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("policy mutation committed after audit failure")
        finally:
            db.append_audit_event = original_append_audit_event
        if db.get_control_plane_approval(policy_rollback_approval_id)["status"] != "approved":
            raise AssertionError("policy audit failure consumed its approval")
        policy_after_rollback = policy_bundle.get_policy_snapshot()
        if (
            policy_before_rollback is None
            or policy_after_rollback is None
            or policy_after_rollback.hash != policy_before_rollback.hash
            or db.get_policy_high_water() != high_water_before_rollback
        ):
            raise AssertionError("policy audit failure changed active policy state")
        retried_policy = app_module.policy_publish(rollback_publish, identity=requester)
        if retried_policy.get("published") is not True:
            raise AssertionError("policy approval was not reusable after rollback")

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

        oidc_approver_id = "oidc:credential-approver@example.com"
        authority = db.get_rbac_authority_state()
        provisioned_approver = db.mutate_rbac_role_binding(
            subject_id=oidc_approver_id,
            roles=["credential_owner"],
            status="active",
            expected_generation=authority["generation"],
            actor_id=requester.user_id,
            reason="approval revocation fixture",
            event_type="rbac.role_changed",
            event={"test": "approver_commit_time_authorization"},
        )
        revocation_approval = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="revoked-approver",
            payload_digest="sha256:" + "d" * 64,
            requester_id=requester.user_id,
            request={"summary": "approver revocation test"},
            ttl_seconds=300,
        )
        if db.approve_control_plane_approval(
            revocation_approval["id"], actor_id=oidc_approver_id
        ) is None:
            raise AssertionError("OIDC approver fixture was not approved")
        db.mutate_rbac_role_binding(
            subject_id=oidc_approver_id,
            roles=[],
            status="deprovisioned",
            expected_generation=provisioned_approver["generation"],
            actor_id=requester.user_id,
            reason="revoke before approval consumption",
            event_type="rbac.deprovisioned",
            event={"test": "approver_commit_time_authorization"},
        )
        revoked_consumption = db.consume_control_plane_approval(
            revocation_approval["id"],
            action="credential.create",
            resource_id="revoked-approver",
            payload_digest="sha256:" + "d" * 64,
            actor_id=requester.user_id,
            required_approver_roles={"credential_owner"},
        )
        if revoked_consumption != {
            "ok": False,
            "reason": "approval_approver_role_revoked",
        }:
            raise AssertionError(
                f"revoked OIDC approver was not rejected: {revoked_consumption}"
            )
        if db.get_control_plane_approval(revocation_approval["id"])["status"] != "approved":
            raise AssertionError("rejected OIDC approval was consumed")

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
