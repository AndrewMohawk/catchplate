#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["CATCHPLATE_DATA_DIR"] = tmp
        for store in ("METADATA", "GRANT", "AUDIT"):
            os.environ[f"CATCHPLATE_{store}_STORE_BACKEND"] = "sqlite"
            os.environ.pop(f"CATCHPLATE_{store}_STORE_POSTGRES_DSN", None)
        os.environ["CATCHPLATE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["CATCHPLATE_DEV_AUTHENTICATOR"] = "1"
        os.environ["CATCHPLATE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["CATCHPLATE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["CATCHPLATE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from fastapi import HTTPException

        from catchplate import app as app_module
        from catchplate import db, grants, webauthn
        from catchplate.auth import AdminIdentity

        db.init_db()
        user_id = "user:demo"
        dev_credential = webauthn.create_dev_credential(user_id)
        run_suffix = hashlib.sha256(
            dev_credential["credential_id"].encode("utf-8")
        ).hexdigest()[:16]

        mutation_payload = {
            "credential_id": "cred-demo-bearer",
            "changes": {"secret": "new-production-token", "metadata": {"scope": "gmail.readonly"}},
        }
        payload_digest = sha256_prefixed_json(mutation_payload)
        options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
        )
        serialized_options = canonical_json(options)
        if "new-production-token" in serialized_options:
            raise AssertionError("control-plane mutation challenge leaked plaintext credential material")
        if payload_digest not in serialized_options:
            raise AssertionError("control-plane mutation challenge did not bind the payload digest")

        assertion = webauthn.dev_assertion(options["publicKey"]["challenge"])
        verified = webauthn.verify_control_plane_mutation_assertion(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
            assertion=assertion,
        )
        if verified.get("method") != "webauthn" or verified.get("payload_digest") != payload_digest:
            raise AssertionError(f"mutation MFA verification returned unexpected result: {verified}")
        if verified.get("user_verified") is not True:
            raise AssertionError(f"mutation MFA did not require user verification: {verified}")

        try:
            webauthn.verify_control_plane_mutation_assertion(
                user_id=user_id,
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=payload_digest,
                authn_policy={"userVerification": "required"},
                assertion=assertion,
            )
        except webauthn.WebAuthnError:
            pass
        else:
            raise AssertionError("control-plane mutation MFA assertion replay unexpectedly succeeded")

        mismatch_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=payload_digest,
            authn_policy={"userVerification": "required"},
        )
        mismatch_assertion = webauthn.dev_assertion(mismatch_options["publicKey"]["challenge"])
        try:
            webauthn.verify_control_plane_mutation_assertion(
                user_id=user_id,
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=sha256_prefixed_json({"credential_id": "cred-demo-bearer", "changes": {"secret": "tampered"}}),
                authn_policy={"userVerification": "required"},
                assertion=mismatch_assertion,
            )
        except webauthn.WebAuthnError as exc:
            if "payload_digest mismatch" not in str(exc):
                raise AssertionError(f"mutation MFA failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("control-plane mutation MFA accepted a mismatched payload digest")

        identity = AdminIdentity(user_id, frozenset({"admin", "policy_author"}), "admin-token-header")
        app_digest = sha256_prefixed_json({"credential_id": "cred-demo-bearer", "changes": {"metadata": {"scope": "gmail.readonly"}}})
        try:
            app_module._require_control_plane_mutation_mfa(
                action="credential.update",
                resource_id="cred-demo-bearer",
                payload_digest=app_digest,
                mfa=None,
                identity=identity,
            )
        except HTTPException as exc:
            if exc.status_code != 412:
                raise AssertionError(f"mutation MFA helper failed with wrong status: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("mutation MFA helper accepted a missing assertion while enforcement is enabled")

        app_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=app_digest,
            authn_policy={"userVerification": "required"},
        )
        app_assertion = webauthn.dev_assertion(app_options["publicKey"]["challenge"])
        app_verified = app_module._require_control_plane_mutation_mfa(
            action="credential.update",
            resource_id="cred-demo-bearer",
            payload_digest=app_digest,
            mfa={"assertion": app_assertion},
            identity=identity,
        )
        if not app_verified or app_verified.get("method") != "webauthn":
            raise AssertionError(f"mutation MFA helper did not verify assertion: {app_verified}")

        legacy_digest = sha256_prefixed_json({"legacy": True})
        legacy_resource = f"cred-legacy-approval-{run_suffix}"
        legacy_approval = db.ensure_control_plane_approval(
            action="credential.update",
            resource_id=legacy_resource,
            payload_digest=legacy_digest,
            requester_id="user:legacy-requester",
            request={"legacy": True},
            ttl_seconds=300,
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE control_plane_approvals "
                "SET status = 'approved', approved_by = 'user:legacy-approver' "
                "WHERE id = ?",
                (legacy_approval["id"],),
            )
        replacement = db.ensure_control_plane_approval(
            action="credential.update",
            resource_id=legacy_resource,
            payload_digest=legacy_digest,
            requester_id="user:legacy-requester",
            request={"legacy": True},
            ttl_seconds=300,
            require_webauthn=True,
        )
        if replacement["id"] == legacy_approval["id"] or replacement["status"] != "pending":
            raise AssertionError(
                f"WebAuthn enforcement reused an unusable legacy approval: {replacement}"
            )
        invalidated_legacy = db.get_control_plane_approval(legacy_approval["id"])
        if invalidated_legacy is None or invalidated_legacy["status"] != "invalidated":
            raise AssertionError(
                f"legacy approval was not invalidated under WebAuthn enforcement: {invalidated_legacy}"
            )

        approval_action = "credential.update"
        approval_resource = f"cred-approved-with-webauthn-{run_suffix}"
        approval_payload_digest = sha256_prefixed_json(
            {"credential_id": approval_resource, "changes": {"status": "active"}}
        )
        control_plane_approval = db.ensure_control_plane_approval(
            action=approval_action,
            resource_id=approval_resource,
            payload_digest=approval_payload_digest,
            requester_id="user:requester",
            request={"credential_id": approval_resource},
            ttl_seconds=300,
        )
        try:
            app_module.control_plane_approval_approve(
                control_plane_approval["id"],
                payload=app_module.ControlPlaneApprovalDecision(note="reviewed"),
                identity=identity,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            if (
                exc.status_code != 412
                or detail.get("error") != "control_plane_webauthn_required"
                or detail.get("action") != approval_action
                or detail.get("resourceId") != approval_resource
                or detail.get("payloadDigest") != approval_payload_digest
                or detail.get("approvalId") != control_plane_approval["id"]
            ):
                raise AssertionError(
                    f"control-plane approval returned the wrong WebAuthn challenge: {exc.status_code} {exc.detail}"
                ) from exc
        else:
            raise AssertionError("control-plane approval accepted no WebAuthn assertion")

        wrong_binding_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action=approval_action,
            resource_id=f"different-credential-{run_suffix}",
            payload_digest=approval_payload_digest,
            authn_policy={"userVerification": "required"},
        )
        wrong_binding_assertion = webauthn.dev_assertion(
            wrong_binding_options["publicKey"]["challenge"]
        )
        try:
            app_module.control_plane_approval_approve(
                control_plane_approval["id"],
                payload=app_module.ControlPlaneApprovalDecision(
                    note="wrong binding",
                    mfa={"assertion": wrong_binding_assertion},
                ),
                identity=identity,
            )
        except HTTPException as exc:
            if exc.status_code != 403 or "resource_id mismatch" not in str(exc.detail):
                raise AssertionError(
                    f"control-plane approval rejected a mismatched assertion incorrectly: {exc.status_code} {exc.detail}"
                ) from exc
        else:
            raise AssertionError("control-plane approval accepted a mismatched WebAuthn binding")

        sibling_approval = db.ensure_control_plane_approval(
            action=approval_action,
            resource_id=approval_resource,
            payload_digest=approval_payload_digest,
            requester_id="user:other-requester",
            request={"credential_id": approval_resource},
            ttl_seconds=300,
        )
        replay_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action=approval_action,
            resource_id=approval_resource,
            payload_digest=approval_payload_digest,
            authn_policy={"userVerification": "required"},
            approval_context=control_plane_approval,
        )
        replay_assertion = webauthn.dev_assertion(
            replay_options["publicKey"]["challenge"]
        )
        try:
            app_module.control_plane_approval_approve(
                sibling_approval["id"],
                payload=app_module.ControlPlaneApprovalDecision(
                    note="cross-record replay",
                    mfa={"assertion": replay_assertion},
                ),
                identity=identity,
            )
        except HTTPException as exc:
            if exc.status_code != 403 or "control_plane_approval_id mismatch" not in str(
                exc.detail
            ):
                raise AssertionError(
                    "approval-record replay was rejected for the wrong reason: "
                    f"{exc.status_code} {exc.detail}"
                ) from exc
        else:
            raise AssertionError(
                "an assertion for one control-plane approval authorized a sibling record"
            )

        approval_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action=approval_action,
            resource_id=approval_resource,
            payload_digest=approval_payload_digest,
            authn_policy={"userVerification": "required"},
            approval_context=control_plane_approval,
        )
        approval_assertion = webauthn.dev_assertion(
            approval_options["publicKey"]["challenge"]
        )
        approved_control_plane = app_module.control_plane_approval_approve(
            control_plane_approval["id"],
            payload=app_module.ControlPlaneApprovalDecision(
                note="reviewed with passkey",
                mfa={"assertion": approval_assertion},
            ),
            identity=identity,
        )
        if approved_control_plane.get("status") != "approved":
            raise AssertionError(
                f"WebAuthn-bound control-plane approval was not approved: {approved_control_plane}"
            )
        if "approval_authn" in approved_control_plane:
            raise AssertionError("control-plane approval API exposed persisted WebAuthn evidence")
        with db.connect() as conn:
            stored_authn = json.loads(
                conn.execute(
                    "SELECT approval_authn FROM control_plane_approvals WHERE id = ?",
                    (control_plane_approval["id"],),
                ).fetchone()["approval_authn"]
            )
        forbidden_evidence = {"credential_id", "aaguid", "sign_count", "challenge_id"}
        if forbidden_evidence.intersection(stored_authn):
            raise AssertionError(
                f"control-plane approval persisted unnecessary authenticator identifiers: {stored_authn}"
            )

        active_credential = db.get_webauthn_credential(dev_credential["credential_id"])
        if active_credential is None:
            raise AssertionError("dev WebAuthn credential disappeared before explicit revocation")
        if (
            approved_control_plane.get("approver_webauthn_credential_id")
            != active_credential["id"]
        ):
            raise AssertionError(
                "control-plane approval did not persist its verified WebAuthn credential record"
            )
        revocation_approval_id = f"approval-revocation-{active_credential['id']}"
        revocation_grant_id = f"grant-revocation-{active_credential['id']}"
        now_s = db.iso_now()
        with db.connect() as conn:
            conn.execute(
                """
                INSERT INTO approval_requests (
                    id, method, url, status, requested_at, expires_at,
                    approver_webauthn_credential_id
                ) VALUES (?, 'POST', 'https://example.test/write', 'approved', ?, ?, ?)
                """,
                (revocation_approval_id, now_s, now_s, active_credential["id"]),
            )
            grant_fields = {
                "grant_id": revocation_grant_id,
                "approval_request_id": revocation_approval_id,
                "principal_id": "agent:revocation-test",
                "route_id": "route-revocation-test",
                "credential_id": "credential-revocation-test",
                "credential_version": 1,
                "policy_hash": "sha256:" + "1" * 64,
                "request_digest": "sha256:" + "2" * 64,
                "operation_digest": "sha256:" + "3" * 64,
                "approver_webauthn_credential_id": active_credential["id"],
                "uses_remaining": 1,
                "valid_from": now_s,
                "expires_at": now_s,
                "created_at": now_s,
            }
            if grants.uses_postgres():
                grants.create_grant(
                    **grant_fields,
                    connection=conn.raw_connection,
                    require_created=True,
                )
            else:
                conn.execute(
                    """
                    INSERT INTO approval_grants (
                        id, approval_request_id, state, principal_id, route_id,
                        credential_id, credential_version, policy_hash,
                        request_digest, operation_digest, uses_remaining, valid_from,
                        expires_at, created_at,
                        approver_webauthn_credential_id
                    ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        revocation_grant_id,
                        revocation_approval_id,
                        "agent:revocation-test",
                        "route-revocation-test",
                        "credential-revocation-test",
                        1,
                        "sha256:" + "1" * 64,
                        "sha256:" + "2" * 64,
                        "sha256:" + "3" * 64,
                        now_s,
                        now_s,
                        now_s,
                        active_credential["id"],
                    ),
                )
        revocation_reason = "operator requested credential retirement"
        try:
            app_module.webauthn_credential_revoke(
                active_credential["id"],
                app_module.WebAuthnCredentialRevoke(reason=revocation_reason),
                identity=identity,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            if (
                exc.status_code != 412
                or detail.get("error") != "control_plane_webauthn_required"
                or detail.get("action") != "webauthn.credential.revoke"
            ):
                raise AssertionError(
                    f"revocation failed before the expected MFA challenge: {exc.status_code} {exc.detail}"
                ) from exc
            revocation_payload_digest = detail.get("payloadDigest")
        else:
            raise AssertionError("WebAuthn credential revocation bypassed mutation MFA")
        revocation_options = webauthn.control_plane_mutation_options(
            user_id=user_id,
            action="webauthn.credential.revoke",
            resource_id=active_credential["id"],
            payload_digest=revocation_payload_digest,
            authn_policy={"userVerification": "required"},
        )
        revocation_assertion = webauthn.dev_assertion(
            revocation_options["publicKey"]["challenge"]
        )
        revoked_result = app_module.webauthn_credential_revoke(
            active_credential["id"],
            app_module.WebAuthnCredentialRevoke(
                reason=revocation_reason,
                mfa={"assertion": revocation_assertion},
            ),
            identity=identity,
        )
        if not revoked_result.get("ok"):
            raise AssertionError(f"explicit WebAuthn credential revocation failed: {revoked_result}")
        if revoked_result.get("revokedGrantCount") != 1:
            raise AssertionError(
                f"credential revocation did not cancel its active JIT grant: {revoked_result}"
            )
        if revoked_result.get("revokedControlPlaneApprovalCount") != 1:
            raise AssertionError(
                "credential revocation did not invalidate its approved control-plane authority: "
                f"{revoked_result}"
            )
        with db.connect() as conn:
            grant = conn.execute(
                "SELECT state, uses_remaining FROM approval_grants WHERE id = ?",
                (revocation_grant_id,),
            ).fetchone()
        if grant is None or grant["state"] != "revoked" or grant["uses_remaining"] != 0:
            raise AssertionError(f"revoked authenticator left a usable JIT grant: {dict(grant or {})}")
        invalidated_approval = db.get_control_plane_approval(
            control_plane_approval["id"]
        )
        if invalidated_approval is None or invalidated_approval["status"] != "invalidated":
            raise AssertionError(
                "revoked authenticator left a control-plane approval usable: "
                f"{invalidated_approval}"
            )
        invalidated_consumption = db.consume_control_plane_approval(
            control_plane_approval["id"],
            action=approval_action,
            resource_id=approval_resource,
            payload_digest=approval_payload_digest,
            actor_id="user:requester",
        )
        if invalidated_consumption != {
            "ok": False,
            "reason": "approval_invalidated",
        }:
            raise AssertionError(
                "revoked authenticator approval did not fail closed at consumption: "
                f"{invalidated_consumption}"
            )
        revoked = revoked_result["credential"]
        expected_revocation = {
            "revoked_by": identity.user_id,
            "revocation_reason": revocation_reason,
            "revocation_source": "explicit",
        }
        for field, expected in expected_revocation.items():
            if revoked.get(field) != expected:
                raise AssertionError(f"explicit revocation did not retain {field}: {revoked}")
        if not revoked.get("revoked_at"):
            raise AssertionError(f"explicit revocation did not retain its timestamp: {revoked}")

        if db.get_webauthn_credential(active_credential["credential_id"]) is not None:
            raise AssertionError("active-only credential lookup returned an explicitly revoked credential")
        retained = db.get_webauthn_credential(
            active_credential["credential_id"], include_revoked=True
        )
        if retained is None:
            raise AssertionError("revoked credential history was not retained")
        for field, expected in expected_revocation.items():
            if retained.get(field) != expected:
                raise AssertionError(f"retained credential history lost {field}: {retained}")

        prior_sign_count = int(retained["sign_count"])
        if db.compare_and_swap_webauthn_sign_count(
            retained["credential_id"],
            expected_sign_count=prior_sign_count,
            new_sign_count=prior_sign_count + 1,
        ):
            raise AssertionError("sign-counter CAS updated an explicitly revoked credential")
        retained_after_cas = db.get_webauthn_credential(
            retained["credential_id"], include_revoked=True
        )
        if retained_after_cas is None or int(retained_after_cas["sign_count"]) != prior_sign_count:
            raise AssertionError(f"failed sign-counter CAS changed revoked credential history: {retained_after_cas}")

        try:
            db.create_webauthn_credential(
                credential_id=retained["credential_id"],
                user_id="user:replacement",
                label="reused revoked credential",
                public_key_cose=retained["public_key_cose"],
                sign_count=0,
                aaguid=retained["aaguid"],
                authenticator_class=retained["authenticator_class"],
                transports=retained["transports"],
            )
        except (ValueError, sqlite3.IntegrityError):
            pass
        else:
            raise AssertionError("a revoked WebAuthn credential ID was reused")

        try:
            app_module.webauthn_register_options(
                app_module.WebAuthnRegistrationStart(label="replacement authenticator"),
                identity=identity,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            if (
                exc.status_code != 412
                or detail.get("error") != "control_plane_webauthn_required"
                or detail.get("action") != "webauthn.credential.register"
            ):
                raise AssertionError(
                    f"revoked credential history failed closed for replacement enrollment: {exc.status_code} {exc.detail}"
                ) from exc
        else:
            raise AssertionError("revoked credential history reset first-enrollment bootstrap")

    print(json.dumps({"control_plane_mutation_mfa": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
