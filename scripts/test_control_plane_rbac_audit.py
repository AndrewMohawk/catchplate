#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import sys
import tempfile
import threading
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


def expect_generation_conflict(func: Any, *, expected: int, current: int) -> None:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        if exc.status_code != 409 or exc.detail != {
            "error": "rbac_generation_conflict",
            "expectedGeneration": expected,
            "currentGeneration": current,
        }:
            raise AssertionError(
                f"stale RBAC mutation failed incorrectly: {exc.status_code} {exc.detail}"
            ) from exc
        return
    raise AssertionError("stale RBAC mutation unexpectedly succeeded")


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
        for store in ("METADATA", "GRANT", "AUDIT"):
            os.environ[f"SERVERWARE_{store}_STORE_BACKEND"] = "sqlite"
            os.environ.pop(f"SERVERWARE_{store}_STORE_POSTGRES_DSN", None)
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
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
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"bootstrap audit outbox did not drain: {delivery}")
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
        role_payload = app_module.RoleBindingUpdate(
            roles=["auditor", "policy_author"],
            expectedGeneration=0,
            reason="join on-call",
        )
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
        with db.connect() as conn:
            historical_active_row = dict(
                conn.execute(
                    "SELECT * FROM rbac_role_bindings WHERE subject_id = ?",
                    (subject_id,),
                ).fetchone()
            )
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
        unaffected_payload = app_module.RoleBindingUpdate(
            roles=["auditor"],
            expectedGeneration=updated["generation"],
            reason="security review",
        )
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
        unaffected_updated = app_module.rbac_role_binding_update(
            unaffected_subject_id,
            unaffected_payload,
            identity=identity,
        )
        unaffected_token = sign_jwt(
            private_key,
            kid=kid,
            issuer=issuer,
            audience=audience,
            roles=["admin"],
            subject="auditor@example.com",
        )

        deprovision_payload = app_module.DeprovisionSubjectRequest(
            subjectId=subject_id,
            expectedGeneration=unaffected_updated["generation"],
            reason="left team",
        )
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

        with db.connect() as conn:
            deprovisioned_row = dict(
                conn.execute(
                    "SELECT * FROM rbac_role_bindings WHERE subject_id = ?",
                    (subject_id,),
                ).fetchone()
            )
            conn.execute(
                """
                UPDATE rbac_role_bindings
                SET roles_json = ?, status = ?, generation = ?, binding_digest = ?,
                    updated_at = ?, updated_by = ?, reason = ?,
                    deprovisioned_at = ?, deprovisioned_by = ?
                WHERE subject_id = ?
                """,
                (
                    historical_active_row["roles_json"],
                    historical_active_row["status"],
                    historical_active_row["generation"],
                    historical_active_row["binding_digest"],
                    historical_active_row["updated_at"],
                    historical_active_row["updated_by"],
                    historical_active_row["reason"],
                    historical_active_row["deprovisioned_at"],
                    historical_active_row["deprovisioned_by"],
                    subject_id,
                ),
            )
        try:
            auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
        except HTTPException as exc:
            if exc.status_code != 503 or "unavailable" not in str(exc.detail):
                raise AssertionError(
                    "historical RBAC replay failed incorrectly: "
                    f"{exc.status_code} {exc.detail}"
                ) from exc
        else:
            raise AssertionError("historical active RBAC row replay restored authorization")
        with db.connect() as conn:
            conn.execute(
                """
                UPDATE rbac_role_bindings
                SET roles_json = ?, status = ?, generation = ?, binding_digest = ?,
                    updated_at = ?, updated_by = ?, reason = ?,
                    deprovisioned_at = ?, deprovisioned_by = ?
                WHERE subject_id = ?
                """,
                (
                    deprovisioned_row["roles_json"],
                    deprovisioned_row["status"],
                    deprovisioned_row["generation"],
                    deprovisioned_row["binding_digest"],
                    deprovisioned_row["updated_at"],
                    deprovisioned_row["updated_by"],
                    deprovisioned_row["reason"],
                    deprovisioned_row["deprovisioned_at"],
                    deprovisioned_row["deprovisioned_by"],
                    subject_id,
                ),
            )
            conn.execute(
                "UPDATE rbac_authority_state SET verified_binding_table_revision = "
                "binding_table_revision WHERE authority_id = 1"
            )

        unaffected_identity = auth.require_admin(FakeRequest(unaffected_token), x_serverware_admin_token=None)
        if unaffected_identity.roles != frozenset({"auditor"}):
            raise AssertionError(f"deprovisioning another subject changed this binding: {unaffected_identity}")

        reprovision_payload = app_module.RoleBindingUpdate(
            roles=["approver"],
            expectedGeneration=deprovisioned["generation"],
            reason="returned to approval duty",
        )
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

        current_generation = db.get_rbac_authority_state()["generation"]
        stale_generation = current_generation - 1
        stale_role_payload = app_module.RoleBindingUpdate(
            roles=["auditor"],
            expectedGeneration=stale_generation,
            reason="stale generation preflight",
        )
        stale_role_digest = app_module._rbac_change_payload_digest(
            "oidc:stale-role@example.com", stale_role_payload
        )
        stale_role_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.role.change",
                resource_id="oidc:stale-role@example.com",
                payload_digest=stale_role_digest,
            )
        }
        for _ in range(2):
            expect_generation_conflict(
                lambda: app_module.rbac_role_binding_update(
                    "oidc:stale-role@example.com",
                    stale_role_payload,
                    identity=identity,
                ),
                expected=stale_generation,
                current=current_generation,
            )

        stale_deprovision_payload = app_module.DeprovisionSubjectRequest(
            subjectId=subject_id,
            expectedGeneration=stale_generation,
            reason="stale generation preflight",
        )
        stale_deprovision_digest = app_module._rbac_deprovision_payload_digest(
            stale_deprovision_payload
        )
        stale_deprovision_payload.mfa = {
            "assertion": sign_mutation_assertion(
                app_module,
                webauthn,
                user_id=user_id,
                action="rbac.deprovision",
                resource_id=subject_id,
                payload_digest=stale_deprovision_digest,
            )
        }
        for _ in range(2):
            expect_generation_conflict(
                lambda: app_module.rbac_deprovision_subject(
                    stale_deprovision_payload, identity=identity
                ),
                expected=stale_generation,
                current=current_generation,
            )

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
            projected_file_identity = auth.require_admin(
                FakeRequest(operator_token),
                x_serverware_admin_token=None,
            )
            if projected_file_identity.roles != frozenset({"approver"}):
                raise AssertionError(
                    "filesystem projection changed database-authoritative RBAC"
                )
            repaired = db.project_rbac_authority_state()
            repaired_file = json.loads(rbac_path.read_text())
            if (
                repaired_file.get("generation") != repaired["generation"]
                or repaired_file.get("state_digest") != repaired["state_digest"]
            ):
                raise AssertionError("RBAC projection was not repaired from database authority")

            with db.connect() as conn:
                stored = conn.execute(
                    "SELECT roles_json FROM rbac_role_bindings WHERE subject_id = ?",
                    (subject_id,),
                ).fetchone()["roles_json"]
                conn.execute(
                    "UPDATE rbac_role_bindings SET roles_json = ? WHERE subject_id = ?",
                    ('["admin"]', subject_id),
                )
            try:
                auth.require_admin(FakeRequest(operator_token), x_serverware_admin_token=None)
            except HTTPException as exc:
                if exc.status_code != 503 or "unavailable" not in str(exc.detail):
                    raise AssertionError(
                        "invalid database RBAC state failed incorrectly: "
                        f"{exc.status_code} {exc.detail}"
                    ) from exc
            else:
                raise AssertionError("invalid database RBAC state failed open")
            with db.connect() as conn:
                conn.execute(
                    "UPDATE rbac_role_bindings SET roles_json = ? WHERE subject_id = ?",
                    (stored, subject_id),
                )
                conn.execute(
                    "UPDATE rbac_authority_state SET verified_binding_table_revision = "
                    "binding_table_revision WHERE authority_id = 1"
                )

            local_identity = auth.require_admin(FakeRequest(auth.admin_token()), x_serverware_admin_token=None)
            if local_identity.auth_method != "bearer-token":
                raise AssertionError(f"local admin token was affected by RBAC state: {local_identity}")
        finally:
            rbac_path.write_bytes(valid_rbac_state)
            auth.RELEASE_CHANNEL = original_release_channel

        race_generation = db.get_rbac_authority_state()["generation"]
        race_barrier = threading.Barrier(2)

        def race_writer(index: int) -> dict[str, Any]:
            race_barrier.wait()
            try:
                result = db.mutate_rbac_role_binding(
                    subject_id=f"oidc:race-{index}@example.com",
                    roles=["auditor"],
                    status="active",
                    expected_generation=race_generation,
                    actor_id=user_id,
                    reason="generation race",
                    event_type="rbac.role_changed",
                    event={"test": "generation_race"},
                )
                return {"status": "committed", "result": result}
            except db.RBACGenerationConflictError as exc:
                return {
                    "status": "conflict",
                    "current_generation": exc.current_generation,
                }

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            race_results = list(executor.map(race_writer, (1, 2)))
        if sorted(item["status"] for item in race_results) != [
            "committed",
            "conflict",
        ]:
            raise AssertionError(f"RBAC generation race was not linearized: {race_results}")
        post_race = db.get_rbac_authority_state()
        if post_race["generation"] != race_generation + 1:
            raise AssertionError(f"RBAC race advanced generation incorrectly: {post_race}")
        race_bindings = [
            subject
            for subject in post_race["subjects"]
            if subject.startswith("oidc:race-")
        ]
        if len(race_bindings) != 1:
            raise AssertionError(f"RBAC race committed multiple writers: {race_bindings}")

        rollback_generation = post_race["generation"]
        original_append_audit_event = db.append_audit_event

        def reject_audit_append(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise db.AuditStoreError("injected RBAC audit failure")

        db.append_audit_event = reject_audit_append
        try:
            try:
                db.mutate_rbac_role_binding(
                    subject_id="oidc:audit-rollback@example.com",
                    roles=["auditor"],
                    status="active",
                    expected_generation=rollback_generation,
                    actor_id=user_id,
                    reason="must roll back",
                    event_type="rbac.role_changed",
                    event={"test": "audit_rollback"},
                )
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("RBAC mutation committed after audit append failure")
        finally:
            db.append_audit_event = original_append_audit_event
        rolled_back = db.get_rbac_authority_state()
        if (
            rolled_back["generation"] != rollback_generation
            or "oidc:audit-rollback@example.com" in rolled_back["subjects"]
        ):
            raise AssertionError(f"RBAC audit failure did not roll back: {rolled_back}")

        original_projection_writer = db._write_rbac_projection

        def reject_projection(_state: dict[str, Any]) -> None:
            raise db.RBACBindingStoreError("injected RBAC projection failure")

        db._write_rbac_projection = reject_projection
        try:
            projection_pending = db.mutate_rbac_role_binding(
                subject_id="oidc:projection-pending@example.com",
                roles=["auditor"],
                status="active",
                expected_generation=rollback_generation,
                actor_id=user_id,
                reason="projection failure",
                event_type="rbac.role_changed",
                event={"test": "projection_recovery"},
            )
        finally:
            db._write_rbac_projection = original_projection_writer
        if projection_pending["projection"]["status"] != "pending":
            raise AssertionError(
                f"RBAC projection failure was not surfaced: {projection_pending}"
            )
        if db.get_rbac_role_binding("oidc:projection-pending@example.com") is None:
            raise AssertionError("committed RBAC binding depended on file projection")
        recovered_projection = db.project_rbac_authority_state()
        if recovered_projection["generation"] != projection_pending["generation"]:
            raise AssertionError("RBAC projection did not converge after retry")
        forged_projection = json.loads(rbac_path.read_text())
        forged_projection["generation"] = recovered_projection["generation"] + 100
        rbac_path.write_text(json.dumps(forged_projection, sort_keys=True))
        repaired_projection = db.project_rbac_authority_state()
        repaired_file = json.loads(rbac_path.read_text())
        if (
            repaired_projection["generation"] != recovered_projection["generation"]
            or repaired_file["generation"] != recovered_projection["generation"]
        ):
            raise AssertionError(
                f"forged projection generation blocked repair: {repaired_file}"
            )

        oidc_admin_id = "oidc:transaction-admin@example.com"
        provisioned_admin = db.mutate_rbac_role_binding(
            subject_id=oidc_admin_id,
            roles=["admin"],
            status="active",
            expected_generation=recovered_projection["generation"],
            actor_id=user_id,
            reason="commit-time authorization fixture",
            event_type="rbac.role_changed",
            event={"test": "commit_time_actor_authorization"},
        )
        actor_committed = db.mutate_rbac_role_binding(
            subject_id="oidc:transaction-target@example.com",
            roles=["auditor"],
            status="active",
            expected_generation=provisioned_admin["generation"],
            actor_id=oidc_admin_id,
            reason="authorized OIDC admin mutation",
            event_type="rbac.role_changed",
            event={"test": "commit_time_actor_authorization"},
        )
        revoked_admin = db.mutate_rbac_role_binding(
            subject_id=oidc_admin_id,
            roles=[],
            status="deprovisioned",
            expected_generation=actor_committed["generation"],
            actor_id=user_id,
            reason="revoke transaction authority",
            event_type="rbac.deprovisioned",
            event={"test": "commit_time_actor_authorization"},
        )
        try:
            db.mutate_rbac_role_binding(
                subject_id="oidc:transaction-denied@example.com",
                roles=["auditor"],
                status="active",
                expected_generation=revoked_admin["generation"],
                actor_id=oidc_admin_id,
                reason="must fail after actor revocation",
                event_type="rbac.role_changed",
                event={"test": "commit_time_actor_authorization"},
            )
        except db.RBACBindingStoreError as exc:
            if "no longer holds" not in str(exc):
                raise AssertionError(f"revoked RBAC actor failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("revoked OIDC admin committed an RBAC mutation")
        after_actor_rejection = db.get_rbac_authority_state()
        if (
            after_actor_rejection["generation"] != revoked_admin["generation"]
            or "oidc:transaction-denied@example.com" in after_actor_rejection["subjects"]
        ):
            raise AssertionError(
                f"rejected RBAC actor changed authoritative state: {after_actor_rejection}"
            )

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

        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"RBAC audit outbox did not drain: {delivery}")
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
