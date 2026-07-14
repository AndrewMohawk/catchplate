#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_uint(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class FakeRequest:
    def __init__(self, token: str):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.cookies: dict[str, str] = {}


def sign_jwt(
    private_key: Any,
    *,
    kid: str,
    issuer: str,
    audience: str,
    roles: list[str],
    subject: str,
) -> str:
    now = int(time.time())
    header = {"typ": "JWT", "alg": "RS256", "kid": kid}
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 5,
        "serverware_roles": roles,
    }
    encoded_header = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_payload = b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{b64u(signature)}"


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
        issuer = "https://idp.example"
        audience = "serverware-control-plane"
        kid = "serverware-rbac-test"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.public_key().public_numbers()
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": kid,
                    "alg": "RS256",
                    "use": "sig",
                    "n": b64u_uint(numbers.n),
                    "e": b64u_uint(numbers.e),
                }
            ]
        }
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ.pop("SERVERWARE_ADMIN_TOKEN", None)
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"
        os.environ["SERVERWARE_OIDC_ENABLED"] = "1"
        os.environ["SERVERWARE_OIDC_ISSUER"] = issuer
        os.environ["SERVERWARE_OIDC_AUDIENCE"] = audience
        os.environ["SERVERWARE_OIDC_JWKS_JSON"] = json.dumps(jwks, separators=(",", ":"), sort_keys=True)
        os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"

        from fastapi import HTTPException
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

        original_list_credentials = db.list_credentials
        original_list_routes = db.list_routes
        original_list_approvals = db.list_approvals
        original_list_logs = db.list_logs
        db.list_credentials = lambda: [
            {
                "id": "credential-sensitive",
                "metadata": {
                    "provider_subject": "provider-user-123",
                    "scopes": ["scope.read"],
                },
            }
        ]
        db.list_routes = lambda: [{"id": "route-sensitive"}]
        db.list_approvals = lambda status=None, limit=100: [{"id": "approval-sensitive"}]
        db.list_logs = lambda limit=150: [{"id": "log-sensitive"}]
        try:
            approver_bootstrap = app_module.bootstrap(
                identity=AdminIdentity("oidc:approver", frozenset({"approver"}), "oidc-bearer")
            )
            if approver_bootstrap["credentials"] or approver_bootstrap["routes"] or approver_bootstrap["logs"]:
                raise AssertionError(f"approver bootstrap exposed unrelated datasets: {approver_bootstrap}")
            if approver_bootstrap["approvals"] != [{"id": "approval-sensitive"}]:
                raise AssertionError(f"approver bootstrap omitted approvals: {approver_bootstrap}")
            if approver_bootstrap["oauthProviders"]:
                raise AssertionError("approver bootstrap exposed OAuth provider configuration")

            owner_bootstrap = app_module.bootstrap(
                identity=AdminIdentity("oidc:owner", frozenset({"credential_owner"}), "oidc-bearer")
            )
            if owner_bootstrap["credentials"][0]["metadata"]["provider_subject"] != "provider-user-123":
                raise AssertionError(f"credential owner bootstrap omitted credential metadata: {owner_bootstrap}")
            if owner_bootstrap["routes"] or owner_bootstrap["approvals"] or owner_bootstrap["logs"]:
                raise AssertionError(f"credential owner bootstrap exposed unrelated datasets: {owner_bootstrap}")

            auditor_bootstrap = app_module.bootstrap(
                identity=AdminIdentity("oidc:auditor", frozenset({"auditor"}), "oidc-bearer")
            )
            if auditor_bootstrap["credentials"] or auditor_bootstrap["oauthProviders"]:
                raise AssertionError(f"auditor bootstrap exposed credential identity data: {auditor_bootstrap}")
            if not auditor_bootstrap["routes"] or not auditor_bootstrap["approvals"] or not auditor_bootstrap["logs"]:
                raise AssertionError(f"auditor bootstrap omitted audit context: {auditor_bootstrap}")

            author_bootstrap = app_module.bootstrap(
                identity=AdminIdentity("oidc:author", frozenset({"policy_author"}), "oidc-bearer")
            )
            if not author_bootstrap["credentials"] or not author_bootstrap["routes"]:
                raise AssertionError(f"policy author bootstrap omitted authoring context: {author_bootstrap}")
            if author_bootstrap["approvals"] or author_bootstrap["logs"]:
                raise AssertionError(f"policy author bootstrap exposed approval or log datasets: {author_bootstrap}")
        finally:
            db.list_credentials = original_list_credentials
            db.list_routes = original_list_routes
            db.list_approvals = original_list_approvals
            db.list_logs = original_list_logs

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

        operator_token = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=audience,
            roles=["admin", "credential_owner"],
            subject="operator@example.com",
        )
        operator_identity = auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
        if operator_identity.roles != frozenset({"auditor", "policy_author"}):
            raise AssertionError(f"authoritative binding did not replace JWT roles: {operator_identity}")
        auth.require_role("policy_author")(operator_identity)
        try:
            auth.require_role("admin")(operator_identity)
        except HTTPException as exc:
            if exc.status_code != 403:
                raise
        else:
            raise AssertionError("JWT admin role bypassed the authoritative role binding")

        unaffected_subject_id = "oidc:auditor@example.com"
        unaffected_payload = app_module.RoleBindingUpdate(roles=["auditor"], reason="security review")
        unaffected_digest = app_module._rbac_change_payload_digest(unaffected_subject_id, unaffected_payload)
        unaffected_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.role.change",
                resource_id=unaffected_subject_id,
                payload_digest=unaffected_digest,
            )
        }
        app_module.rbac_role_binding_update(unaffected_subject_id, unaffected_payload, identity=identity)
        unaffected_token = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=audience,
            roles=["admin"],
            subject="auditor@example.com",
        )

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
        try:
            auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 403 or "deprovisioned" not in str(exc.detail):
                raise AssertionError(f"deprovisioned OIDC subject failed incorrectly: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("deprovisioned OIDC subject retained access with a valid JWT")
        try:
            auth.require_role("policy_author")(operator_identity)
        except HTTPException as exc:
            if exc.status_code != 403 or "deprovisioned" not in str(exc.detail):
                raise AssertionError(f"stale OIDC identity failed incorrectly: {exc.status_code} {exc.detail}") from exc
        else:
            raise AssertionError("require_role trusted an OIDC identity created before deprovisioning")

        unaffected_identity = auth.require_admin(FakeRequest(unaffected_token), x_serverware_admin_token=None)
        if unaffected_identity.roles != frozenset({"auditor"}):
            raise AssertionError(f"deprovisioning another subject changed this binding: {unaffected_identity}")

        reprovision_payload = app_module.RoleBindingUpdate(roles=["approver"], reason="returned to approval duty")
        reprovision_digest = app_module._rbac_change_payload_digest(subject_id, reprovision_payload)
        reprovision_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.role.change",
                resource_id=subject_id,
                payload_digest=reprovision_digest,
            )
        }
        app_module.rbac_role_binding_update(subject_id, reprovision_payload, identity=identity)
        reprovisioned_identity = auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
        if reprovisioned_identity.roles != frozenset({"approver"}):
            raise AssertionError(f"reprovisioned roles were not applied immediately: {reprovisioned_identity}")
        auth.require_role("approver")(reprovisioned_identity)
        refreshed_stale_identity = auth.require_role("approver")(operator_identity)
        if refreshed_stale_identity.roles != frozenset({"approver"}):
            raise AssertionError(f"require_role did not refresh a stale OIDC identity: {refreshed_stale_identity}")

        rbac_path = Path(tmp) / "rbac-bindings.json"
        valid_rbac_state = rbac_path.read_bytes()
        original_release_channel = auth.RELEASE_CHANNEL
        auth.RELEASE_CHANNEL = "prod"
        try:
            unbound_token = sign_jwt(
                private_key,
                kid=kid,
                issuer=issuer,
                audience=audience,
                roles=["admin"],
                subject="unbound@example.com",
            )
            try:
                auth.require_admin(FakeRequest(unbound_token), x_serverware_admin_token=None)
            except HTTPException as exc:
                if exc.status_code != 403 or "not provisioned" not in str(exc.detail):
                    raise AssertionError(f"unbound production OIDC subject failed incorrectly: {exc.status_code} {exc.detail}") from exc
            else:
                raise AssertionError("unbound production OIDC subject was accepted")

            rbac_path.write_text("{not-json")
            try:
                auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
            except HTTPException as exc:
                if exc.status_code != 503 or "unavailable" not in str(exc.detail):
                    raise AssertionError(f"unreadable production RBAC state failed incorrectly: {exc.status_code} {exc.detail}") from exc
            else:
                raise AssertionError("unreadable production RBAC state failed open")

            local_identity = auth.require_admin(FakeRequest(auth.admin_token()), x_serverware_admin_token=None)
            if local_identity.auth_method != "bearer-token":
                raise AssertionError(f"local admin token was affected by RBAC state: {local_identity}")
        finally:
            rbac_path.write_bytes(valid_rbac_state)
            auth.RELEASE_CHANNEL = original_release_channel

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
