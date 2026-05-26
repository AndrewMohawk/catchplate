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


def sign_mutation_assertion(
    app_module: Any,
    webauthn: Any,
    *,
    user_id: str,
    action: str,
    resource_id: str,
    payload_digest: str,
) -> dict[str, Any]:
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action=action,
        resource_id=resource_id,
        payload_digest=payload_digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "new-admin-token" in serialized_options:
        raise AssertionError("control-plane WebAuthn challenge leaked token material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ.pop("SERVERWARE_ADMIN_TOKEN", None)
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import auth, db, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:admin"
        identity = AdminIdentity(user_id, frozenset({"admin", "auditor"}), "admin-token-header")
        webauthn.create_dev_credential(user_id)

        app_module.bootstrap(identity=identity)
        audits = db.list_audit_events(limit=20)
        if "control_plane.bootstrap" not in [item["event_type"] for item in audits]:
            raise AssertionError(f"bootstrap did not write an audit event: {audits}")

        subject_id = "oidc:operator@example.com"
        role_payload = app_module.RoleBindingUpdate(roles=["auditor", "policy_author"], reason="join on-call")
        role_digest = app_module._rbac_change_payload_digest(subject_id, role_payload)
        role_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.role.change",
                resource_id=subject_id,
                payload_digest=role_digest,
            )
        }
        updated = app_module.rbac_role_binding_update(subject_id, role_payload, identity=identity)
        if updated["binding"]["roles"] != ["auditor", "policy_author"]:
            raise AssertionError(f"role binding update returned wrong roles: {updated}")
        bindings = app_module.rbac_role_bindings(_=identity)
        if bindings["subjects"][subject_id]["status"] != "active":
            raise AssertionError(f"role binding state was not persisted: {bindings}")

        deprovision_payload = app_module.DeprovisionSubjectRequest(subjectId=subject_id, reason="left team")
        deprovision_digest = app_module._rbac_deprovision_payload_digest(deprovision_payload)
        deprovision_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.deprovision",
                resource_id=subject_id,
                payload_digest=deprovision_digest,
            )
        }
        deprovisioned = app_module.rbac_deprovision_subject(deprovision_payload, identity=identity)
        if deprovisioned["binding"]["status"] != "deprovisioned" or deprovisioned["binding"]["roles"]:
            raise AssertionError(f"subject was not deprovisioned: {deprovisioned}")

        old_token = auth.admin_token()
        rotate_payload = app_module.AdminTokenRotateRequest(reason="scheduled rotation")
        rotate_digest = app_module._admin_token_rotation_payload_digest(rotate_payload)
        rotate_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="control_plane.token.rotate",
                resource_id="admin-token",
                payload_digest=rotate_digest,
            )
        }
        rotated = app_module.control_plane_admin_token_rotate(rotate_payload, identity=identity)
        if not auth.check_admin_token(rotated["token"]):
            raise AssertionError("rotated admin token is not accepted")
        if auth.check_admin_token(old_token):
            raise AssertionError("old admin token still works after rotation")

        audits = db.list_audit_events(limit=50)
        event_types = [item["event_type"] for item in audits]
        for expected in ("rbac.role_changed", "rbac.deprovisioned", "control_plane.token_rotated"):
            if expected not in event_types:
                raise AssertionError(f"missing {expected} audit event: {event_types}")
        token_event = next(item for item in audits if item["event_type"] == "control_plane.token_rotated")
        serialized_token_event = json.dumps(token_event, sort_keys=True)
        if rotated["token"] in serialized_token_event:
            raise AssertionError("token rotation audit event exposed the new token")
        if token_event["event"].get("new_token_sha256") != rotated["tokenSha256"]:
            raise AssertionError(f"token rotation audit did not bind the new token hash: {token_event}")

    print(json.dumps({"control_plane_rbac_audit": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
