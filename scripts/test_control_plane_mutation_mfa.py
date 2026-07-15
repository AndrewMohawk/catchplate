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
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from fastapi import HTTPException

        from serverware import app as app_module
        from serverware import db, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:demo"
        dev_credential = webauthn.create_dev_credential(user_id)

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

        active_credential = db.get_webauthn_credential(dev_credential["credential_id"])
        if active_credential is None:
            raise AssertionError("dev WebAuthn credential disappeared before explicit revocation")
        now_s = db.iso_now()
        with db.connect() as conn:
            conn.execute(
                """
                INSERT INTO approval_requests (
                    id, method, url, status, requested_at, expires_at,
                    approver_webauthn_credential_id
                ) VALUES (?, 'POST', 'https://example.test/write', 'approved', ?, ?, ?)
                """,
                ("approval-revocation-test", now_s, now_s, active_credential["id"]),
            )
            conn.execute(
                """
                INSERT INTO approval_grants (
                    id, approval_request_id, state, principal_id, route_id,
                    credential_id, credential_version, policy_hash,
                    request_digest, operation_digest, uses_remaining, valid_from,
                    expires_at, created_at, updated_at,
                    approver_webauthn_credential_id
                ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                """,
                (
                    "grant-revocation-test",
                    "approval-revocation-test",
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
        with db.connect() as conn:
            grant = conn.execute(
                "SELECT state, uses_remaining FROM approval_grants WHERE id = ?",
                ("grant-revocation-test",),
            ).fetchone()
        if grant is None or grant["state"] != "revoked" or grant["uses_remaining"] != 0:
            raise AssertionError(f"revoked authenticator left a usable JIT grant: {dict(grant or {})}")
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
