from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from serverware import __version__
from serverware.attestation import attestation_document
from serverware.config import DATA_PLANE_AUDIT_TOKEN, MITMPROXY_CONF_DIR, POLICY_BUNDLE_PATH
from serverware import db, grants, runtime
from serverware.auth import AdminIdentity, admin_status, require_admin, require_role
from serverware.key_release import KeyReleaseError, release_material, status as key_release_status
from serverware.policy_bundle import (
    demo_policy_bundle,
    get_policy_snapshot,
    policy_public_key_hash,
    policy_public_key_pem,
    write_policy_bundle,
)
from serverware.webauthn import (
    WebAuthnError,
    approval_options,
    create_dev_credential,
    dev_assertion,
    registration_options,
    verify_approval_assertion,
    verify_registration,
)
from serverware.webauthn_trust import WebAuthnTrustError, status as webauthn_trust_status, write_trust_bundle


app = FastAPI(title="Serverware", version=__version__)


class CredentialCreate(BaseModel):
    name: str
    kind: str = "bearer"
    secret: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialUpdate(BaseModel):
    name: str | None = None
    kind: str | None = None
    secret: str | None = None
    metadata: dict[str, Any] | None = None


class RouteCreate(BaseModel):
    name: str
    enabled: bool = True
    match_host: str
    match_path_prefix: str = "/"
    credential_id: str | None = None
    injection: dict[str, Any] = Field(default_factory=lambda: {"type": "bearer"})
    policies: list[dict[str, Any]] = Field(default_factory=list)


class RouteUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    match_host: str | None = None
    match_path_prefix: str | None = None
    credential_id: str | None = None
    injection: dict[str, Any] | None = None
    policies: list[dict[str, Any]] | None = None


class ApprovalApprove(BaseModel):
    note: str | None = None
    assertion: dict[str, Any] | None = None


class WebAuthnRegistrationStart(BaseModel):
    label: str = "YubiKey"


class WebAuthnRegistrationFinish(BaseModel):
    label: str = "YubiKey"
    response: dict[str, Any]


class WebAuthnTrustPublish(BaseModel):
    bundle: dict[str, Any]


class DevAssertionRequest(BaseModel):
    challenge: str


class DataPlaneAuditEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(default="decision-gate-rs", min_length=1, max_length=128)
    event: dict[str, Any] = Field(default_factory=dict)


class DataPlaneAuditBatch(BaseModel):
    events: list[DataPlaneAuditEvent] = Field(default_factory=list, max_length=200)


class DataPlaneGrantConsume(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_id: str = Field(alias="principalId", min_length=1)
    route_id: str = Field(alias="routeId", min_length=1)
    credential_ref: str = Field(alias="credentialRef", min_length=1)
    credential_version: int = Field(alias="credentialVersion", ge=1)
    policy_hash: str = Field(alias="policyHash", min_length=1)
    request_digest: str = Field(alias="requestDigest", min_length=1)
    operation_digest: str | None = Field(default=None, alias="operationDigest")
    flow_id: str = Field(alias="flowId", min_length=1)


class KeyReleaseVerify(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    material: str = Field(min_length=1)
    expected_policy_hash: str | None = Field(default=None, alias="expectedPolicyHash")
    expected_ca_spki: str | None = Field(default=None, alias="expectedCaSpki")
    expected_rollback_epoch: int | None = Field(default=None, alias="expectedRollbackEpoch")
    expected_release_channel: str | None = Field(default=None, alias="expectedReleaseChannel")
    expected_provenance_digest: str | None = Field(default=None, alias="expectedProvenanceDigest")
    expected_data_plane_binary_digest: str | None = Field(default=None, alias="expectedDataPlaneBinaryDigest")


@app.on_event("startup")
def startup() -> None:
    db.init_db()
    runtime.start_runtime_workers()
    runtime.start_audit_anchor_worker()
    runtime.start_decision_gate_ca_publisher()


@app.get("/", response_class=HTMLResponse)
@app.get("/approvals", response_class=HTMLResponse)
def index() -> str:
    return UI_HTML


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    ca_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    snapshot = get_policy_snapshot()
    return {
        "ok": True,
        "version": __version__,
        "ca_ready": ca_path.exists(),
        "policy_ready": snapshot is not None,
        "policy_hash": snapshot.hash if snapshot else None,
        **admin_status(),
    }


def _approval_jit_policy(approval: dict[str, Any]) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    route_id = approval.get("route_id")
    route = next((item for item in snapshot.routes if item.id == route_id), None)
    if not route:
        raise HTTPException(status_code=409, detail="approval route is not in the active policy")
    return route.jit or {}


def _approval_authn_policy(jit: dict[str, Any]) -> dict[str, Any]:
    return ((jit.get("approvers") or {}).get("authn") or {})


def _assert_approver_allowed(identity: AdminIdentity, jit: dict[str, Any]) -> None:
    approvers = jit.get("approvers") or {}
    users = set(approvers.get("users") or [])
    if users and "*" not in users and identity.user_id not in users:
        raise HTTPException(status_code=403, detail="current user is not an allowed approver for this route")


def _webauthn_required(authn_policy: dict[str, Any]) -> bool:
    return bool(authn_policy.get("webauthnRequired"))


def _approval_is_expired(approval: dict[str, Any]) -> bool:
    return datetime.fromisoformat(approval["expires_at"]) <= datetime.now(timezone.utc)


@app.get("/attestation")
def attestation(nonce: str | None = None) -> dict[str, Any]:
    return attestation_document(nonce)


@app.get("/ca.pem")
def ca_pem(_: AdminIdentity = Depends(require_role("admin"))) -> FileResponse:
    ca_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        raise HTTPException(status_code=404, detail="mitmproxy CA has not been generated yet")
    return FileResponse(
        ca_path,
        media_type="application/x-pem-file",
        filename="serverware-ca.pem",
        headers={
            "Cache-Control": "no-store",
            "X-Serverware-Debug-Only": "true",
            "X-Serverware-Install-Path": "verify-attestation-first",
        },
    )


@app.get("/api/key-release/status")
def key_release_status_api(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    return key_release_status()


@app.post("/api/key-release/verify")
def key_release_verify(
    payload: KeyReleaseVerify,
    _: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    try:
        return release_material(
            payload.material,
            expected_policy_hash=payload.expected_policy_hash,
            expected_ca_spki=payload.expected_ca_spki,
            expected_rollback_epoch=payload.expected_rollback_epoch,
            expected_release_channel=payload.expected_release_channel,
            expected_provenance_digest=payload.expected_provenance_digest,
            expected_data_plane_binary_digest=payload.expected_data_plane_binary_digest,
        )
    except KeyReleaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/bootstrap")
def bootstrap(_: None = Depends(require_admin)) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else {}
    return {
        "credentials": db.list_credentials(),
        "routes": db.list_routes(),
        "approvals": db.list_approvals(limit=100),
        "logs": db.list_logs(limit=150),
        "ca_ready": (MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem").exists(),
        "policy_ready": snapshot is not None,
        "policy_hash": snapshot.hash if snapshot else None,
        "policy_signature": metadata.get("signature") if isinstance(metadata, dict) else None,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "policy_path": str(POLICY_BUNDLE_PATH),
        **admin_status(),
    }


@app.post("/api/credentials")
def create_credential(payload: CredentialCreate, _: AdminIdentity = Depends(require_role("admin", "policy_author"))) -> dict[str, Any]:
    created = db.create_credential(payload.name, payload.kind, payload.secret, payload.metadata)
    db.record_audit_event(
        "credential.created",
        {
            "credential_id": created["id"],
            "name": created["name"],
            "kind": created["kind"],
            "credential_version": created.get("credential_version"),
            "secret_kek_id": created.get("secret_kek_id"),
        },
    )
    runtime.publish_credential_generation(created["id"], int(created["credential_version"]))
    runtime.publish_credential_lease_from_db(created["id"])
    return created


@app.put("/api/credentials/{credential_id}")
def update_credential(
    credential_id: str,
    payload: CredentialUpdate,
    _: AdminIdentity = Depends(require_role("admin", "policy_author")),
) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True)
    updated = db.update_credential(credential_id, changes)
    if not updated:
        raise HTTPException(status_code=404, detail="credential not found")
    db.record_audit_event(
        "credential.updated",
        {
            "credential_id": credential_id,
            "name": updated["name"],
            "changed_fields": sorted(changes),
            "secret_changed": "secret" in changes,
            "credential_version": updated.get("credential_version"),
            "secret_kek_id": updated.get("secret_kek_id"),
        },
    )
    runtime.publish_credential_generation(credential_id, int(updated["credential_version"]))
    runtime.publish_credential_lease_from_db(credential_id)
    return updated


@app.delete("/api/credentials/{credential_id}")
def delete_credential(credential_id: str, _: AdminIdentity = Depends(require_role("admin", "policy_author"))) -> dict[str, Any]:
    deleted = db.delete_credential(credential_id)
    if deleted:
        db.record_audit_event("credential.deleted", {"credential_id": credential_id})
        runtime.publish_credential_generation(credential_id, deleted=True)
        runtime.publish_credential_lease(credential_id, deleted=True)
    return {"deleted": deleted}


@app.post("/api/routes")
def create_route(payload: RouteCreate, _: AdminIdentity = Depends(require_role("admin", "policy_author"))) -> dict[str, Any]:
    data = payload.model_dump()
    if data.get("credential_id") == "":
        data["credential_id"] = None
    created = db.create_route(data)
    db.record_audit_event(
        "route.created",
        {
            "route_id": created["id"],
            "name": created["name"],
            "match_host": created["match_host"],
            "match_path_prefix": created["match_path_prefix"],
            "credential_id": created["credential_id"],
        },
    )
    return created


@app.put("/api/routes/{route_id}")
def update_route(
    route_id: str,
    payload: RouteUpdate,
    _: AdminIdentity = Depends(require_role("admin", "policy_author")),
) -> dict[str, Any]:
    data = payload.model_dump(exclude_unset=True)
    if data.get("credential_id") == "":
        data["credential_id"] = None
    updated = db.update_route(route_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="route not found")
    db.record_audit_event(
        "route.updated",
        {
            "route_id": route_id,
            "name": updated["name"],
            "changed_fields": sorted(data),
            "match_host": updated["match_host"],
            "match_path_prefix": updated["match_path_prefix"],
            "credential_id": updated["credential_id"],
        },
    )
    return updated


@app.delete("/api/routes/{route_id}")
def delete_route(route_id: str, _: AdminIdentity = Depends(require_role("admin", "policy_author"))) -> dict[str, Any]:
    deleted = db.delete_route(route_id)
    if deleted:
        db.record_audit_event("route.deleted", {"route_id": route_id})
    return {"deleted": deleted}


@app.get("/api/approvals")
def approvals(status: str | None = None, _: AdminIdentity = Depends(require_role("approver", "auditor"))) -> list[dict[str, Any]]:
    return db.list_approvals(status=status, limit=100)


@app.post("/api/approvals/{approval_id}/approve")
def approve(
    approval_id: str,
    ttl_seconds: int = Query(30, ge=1, le=3600),
    payload: ApprovalApprove | None = Body(default=None),
    identity: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"approval is already {approval['status']}")
    if _approval_is_expired(approval):
        raise HTTPException(status_code=409, detail="approval is expired")
    jit = _approval_jit_policy(approval)
    _assert_approver_allowed(identity, jit)
    authn_policy = _approval_authn_policy(jit)
    authn: dict[str, Any]
    if _webauthn_required(authn_policy) or (payload and payload.assertion):
        if not payload or not payload.assertion:
            raise HTTPException(status_code=412, detail="WebAuthn assertion required for this approval")
        try:
            authn = verify_approval_assertion(approval, identity.user_id, authn_policy, payload.assertion)
        except WebAuthnError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    else:
        authn = {"method": identity.auth_method, "user_id": identity.user_id}
    updated = db.approve_request(
        approval_id,
        ttl_seconds=ttl_seconds,
        note=payload.note if payload else None,
        actor_id=identity.user_id,
        authn=authn,
        challenge_id=authn.get("challenge_id"),
    )
    if not updated:
        raise HTTPException(status_code=409, detail="approval state changed before it could be approved")
    gate_publish = runtime.publish_decision_gate_grant(updated)
    if gate_publish.get("enabled"):
        db.record_audit_event(
            "data_plane.grant.publish",
            {
                "approval_request_id": updated["id"],
                "route_id": updated.get("route_id"),
                "principal_id": updated.get("principal_id"),
                "credential_id": updated.get("credential_id"),
                "credential_version": updated.get("credential_version"),
                "policy_hash": updated.get("policy_hash"),
                "request_digest": updated.get("request_digest"),
                "operation_digest": updated.get("operation_digest"),
                "ok": bool(gate_publish.get("ok")),
                "error": gate_publish.get("error"),
                "decision_gate_response": gate_publish.get("response"),
            },
            actor_id=identity.user_id,
        )
    updated["data_plane_grant_publish"] = {
        key: value
        for key, value in gate_publish.items()
        if key != "payload"
    }
    return updated


@app.post("/api/approvals/{approval_id}/deny")
def deny(approval_id: str, identity: AdminIdentity = Depends(require_role("approver"))) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"approval is already {approval['status']}")
    if _approval_is_expired(approval):
        raise HTTPException(status_code=409, detail="approval is expired")
    _assert_approver_allowed(identity, _approval_jit_policy(approval))
    updated = db.deny_request(approval_id, actor_id=identity.user_id)
    if not updated:
        raise HTTPException(status_code=409, detail="approval state changed before it could be denied")
    return updated


@app.post("/api/approvals/{approval_id}/webauthn/options")
def approval_webauthn_options(
    approval_id: str,
    identity: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail="approval is not pending")
    jit = _approval_jit_policy(approval)
    _assert_approver_allowed(identity, jit)
    return approval_options(approval, identity.user_id, _approval_authn_policy(jit))


@app.post("/api/webauthn/register/options")
def webauthn_register_options(
    payload: WebAuthnRegistrationStart,
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> dict[str, Any]:
    return registration_options(identity.user_id, payload.label)


@app.post("/api/webauthn/register/verify")
def webauthn_register_verify(
    payload: WebAuthnRegistrationFinish,
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> dict[str, Any]:
    try:
        credential = verify_registration(identity.user_id, payload.label, payload.response)
    except WebAuthnError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.record_audit_event(
        "webauthn.credential_registered",
        {
            "user_id": identity.user_id,
            "credential_id": credential["credential_id"],
            "authenticator_class": credential["authenticator_class"],
            "aaguid": credential.get("aaguid"),
            "attestation_fmt": credential.get("attestation_fmt"),
            "attestation_trusted": credential.get("attestation_trusted"),
            "attestation_root_sha256": credential.get("attestation_root_sha256"),
        },
        actor_id=identity.user_id,
    )
    return credential


@app.get("/api/webauthn/credentials")
def webauthn_credentials(identity: AdminIdentity = Depends(require_role("admin", "approver"))) -> list[dict[str, Any]]:
    items = []
    for item in db.list_webauthn_credentials(identity.user_id):
        redacted = dict(item)
        redacted.pop("public_key_cose", None)
        redacted.pop("dev_private_key_pem", None)
        items.append(redacted)
    return items


@app.get("/api/webauthn/trust/status")
def webauthn_trust_status_api(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    try:
        return webauthn_trust_status()
    except WebAuthnTrustError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/webauthn/trust/publish")
def webauthn_trust_publish(
    payload: WebAuthnTrustPublish,
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    try:
        result = write_trust_bundle(payload.bundle)
    except WebAuthnTrustError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.record_audit_event(
        "webauthn.trust_bundle.published",
        {
            "bundle_digest": result.get("digest"),
            "sequence": result.get("sequence"),
            "rollback_epoch": result.get("rollback_epoch"),
            "signing_key_id": result.get("signing_key_id"),
        },
        actor_id=identity.user_id,
    )
    return result


@app.post("/api/dev/webauthn/credential")
def dev_webauthn_credential(identity: AdminIdentity = Depends(require_role("admin"))) -> dict[str, Any]:
    try:
        credential = create_dev_credential(identity.user_id)
    except WebAuthnError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.record_audit_event(
        "webauthn.dev_credential_created",
        {"user_id": identity.user_id, "credential_id": credential["credential_id"]},
        actor_id=identity.user_id,
    )
    return credential


@app.post("/api/dev/webauthn/assertion")
def dev_webauthn_assertion(
    payload: DevAssertionRequest,
    _: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    try:
        return dev_assertion(payload.challenge)
    except WebAuthnError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/api/logs")
def logs(limit: int = Query(100, ge=1, le=500), _: AdminIdentity = Depends(require_role("auditor"))) -> list[dict[str, Any]]:
    return db.list_logs(limit=limit)


@app.get("/api/grants/status")
def grant_store_status(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    try:
        return grants.status()
    except grants.GrantStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/metadata/store/status")
def metadata_store_status(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    try:
        return db.metadata_store_status()
    except db.MetadataStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.delete("/api/logs")
def clear_logs(_: AdminIdentity = Depends(require_role("admin"))) -> dict[str, Any]:
    db.clear_logs()
    db.record_audit_event("logs.cleared", {})
    return {"cleared": True}


@app.get("/api/audit")
def audit_events(limit: int = Query(100, ge=1, le=500), _: AdminIdentity = Depends(require_role("auditor"))) -> list[dict[str, Any]]:
    return db.list_audit_events(limit=limit)


@app.get("/api/audit/store/status")
def audit_store_status(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    try:
        return db.audit_store_status()
    except db.AuditStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/data-plane/audit")
def data_plane_audit(
    batch: DataPlaneAuditBatch,
    x_serverware_data_plane_token: str | None = Header(default=None, alias="X-Serverware-Data-Plane-Token"),
) -> dict[str, Any]:
    _require_data_plane_token(x_serverware_data_plane_token)
    for item in batch.events:
        if not item.event_type.startswith("data_plane."):
            raise HTTPException(status_code=400, detail="data-plane audit event_type must start with data_plane.")
    accepted = 0
    for item in batch.events:
        db.record_audit_event(
            item.event_type,
            item.event,
            actor_type="data-plane",
            actor_id=item.actor_id,
        )
        accepted += 1
    return {"ok": True, "accepted": accepted}


@app.post("/api/data-plane/grants/consume")
def data_plane_grant_consume(
    payload: DataPlaneGrantConsume,
    x_serverware_data_plane_token: str | None = Header(default=None, alias="X-Serverware-Data-Plane-Token"),
) -> dict[str, Any]:
    _require_data_plane_token(x_serverware_data_plane_token)
    result = db.consume_jit_grant_result(
        principal_id=payload.principal_id,
        route_id=payload.route_id,
        credential_id=payload.credential_ref,
        credential_version=payload.credential_version,
        policy_hash=payload.policy_hash,
        request_digest=payload.request_digest,
        operation_digest=payload.operation_digest,
        flow_id=payload.flow_id,
    )
    return {"ok": True, **result}


def _require_data_plane_token(x_serverware_data_plane_token: str | None) -> None:
    if not DATA_PLANE_AUDIT_TOKEN:
        raise HTTPException(status_code=503, detail="data-plane authentication is not configured")
    if not x_serverware_data_plane_token or not hmac.compare_digest(
        x_serverware_data_plane_token, DATA_PLANE_AUDIT_TOKEN
    ):
        raise HTTPException(status_code=401, detail="data-plane authentication required")


@app.get("/api/audit/verify")
def audit_verify(
    limit: int | None = Query(default=None, ge=1, le=10000),
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    return db.verify_audit_chain(limit=limit)


@app.get("/api/audit/anchors/status")
def audit_anchor_status(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    return runtime.audit_anchor_status()


@app.post("/api/audit/anchors/flush")
def audit_anchor_flush(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    return runtime.flush_audit_anchor()


@app.get("/api/runtime/metrics")
def runtime_metrics(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, int]:
    return runtime.metrics()


@app.get("/api/policy")
def policy_status(_: AdminIdentity = Depends(require_role("auditor", "policy_author"))) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if not snapshot:
        return {
            "ready": False,
            "policy_hash": None,
            "policy_path": str(POLICY_BUNDLE_PATH),
            "signing_key_id": policy_public_key_hash(),
        }
    metadata = snapshot.raw.get("metadata") or {}
    return {
        "ready": True,
        "policy_hash": snapshot.hash,
        "policy_path": str(POLICY_BUNDLE_PATH),
        "metadata": metadata,
        "bundle": snapshot.raw,
        "public_key_pem": policy_public_key_pem(),
    }


def _upsert_credential(name: str, kind: str, secret: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    existing = next((item for item in db.list_credentials() if item["name"] == name), None)
    if existing:
        return db.update_credential(existing["id"], {"kind": kind, "secret": secret, "metadata": metadata or {}})
    return db.create_credential(name, kind, secret, metadata or {})


def _upsert_route(payload: dict[str, Any]) -> dict[str, Any]:
    existing = next((item for item in db.list_routes() if item["name"] == payload["name"]), None)
    if existing:
        return db.update_route(existing["id"], payload)
    return db.create_route(payload)


def _upsert_policy_route(route_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return db.upsert_route_with_id(route_id, payload)


@app.post("/api/demo/seed")
def seed_demo(_: AdminIdentity = Depends(require_role("admin"))) -> dict[str, Any]:
    policy_snapshot = write_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
    credential = db.upsert_credential_with_id(
        "cred-demo-bearer",
        "Demo bearer token",
        "bearer",
        "demo-token-from-vault",
        {"x_app_id": "demo-x-app"},
    )
    runtime.publish_credential_generation(credential["id"], int(credential["credential_version"]))
    runtime.publish_credential_lease_from_db(credential["id"])
    common = {
        "enabled": True,
        "match_host": "demo-upstream",
        "credential_id": credential["id"],
        "injection": {"type": "bearer"},
    }
    routes = [
        _upsert_policy_route(
            "demo.gmail.recent",
            {
                **common,
                "name": "Demo Gmail recent mailbox",
                "match_path_prefix": "/gmail/v1",
                "policies": [{"type": "gmail_recent", "days": 30, "max_results": 10, "cache_ttl_seconds": 1800}],
            }
        ),
        _upsert_policy_route(
            "demo.approval.legacy",
            {
                **common,
                "name": "Demo approval gate",
                "match_path_prefix": "/approval",
                "policies": [{"type": "approval", "ttl_seconds": 30, "pending_ttl_seconds": 300, "scope": "url"}],
            }
        ),
        _upsert_policy_route(
            "demo.npm.publish.jit",
            {
                **common,
                "name": "Demo NPM publish JIT",
                "match_path_prefix": "/npm",
                "policies": [{"type": "approval", "ttl_seconds": 30, "pending_ttl_seconds": 300, "scope": "request_digest"}],
            }
        ),
        _upsert_policy_route(
            "demo.x.readonly",
            {
                **common,
                "name": "Demo X read-only",
                "match_path_prefix": "/2",
                "policies": [{"type": "x_read_only"}],
            }
        ),
        _upsert_policy_route(
            "demo.echo",
            {
                **common,
                "name": "Demo HTTPS bearer injection",
                "match_path_prefix": "/echo",
                "policies": [],
            }
        ),
        _upsert_policy_route(
            "demo.upload.stream",
            {
                **common,
                "name": "Demo streaming upload",
                "match_path_prefix": "/upload-bytes",
                "policies": [{"type": "request_body_stream", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.jsonl.redact.stream",
            {
                **common,
                "name": "Demo JSONL streaming redaction",
                "match_path_prefix": "/jsonl-redact",
                "policies": [{"type": "jsonl_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.array.redact.stream",
            {
                **common,
                "name": "Demo JSON array streaming redaction",
                "match_path_prefix": "/json-array-redact",
                "policies": [{"type": "json_array_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.sse.redact.stream",
            {
                **common,
                "name": "Demo JSON SSE streaming redaction",
                "match_path_prefix": "/json-sse-redact",
                "policies": [{"type": "json_sse_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.nested.redact.stream",
            {
                **common,
                "name": "Demo nested JSON streaming redaction",
                "match_path_prefix": "/json-nested-redact",
                "policies": [{"type": "json_nested_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.form.urlencoded.redact.stream",
            {
                **common,
                "name": "Demo form-urlencoded streaming redaction",
                "match_path_prefix": "/form-redact",
                "policies": [{"type": "form_urlencoded_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.csv.redact.stream",
            {
                **common,
                "name": "Demo CSV streaming redaction",
                "match_path_prefix": "/csv-redact",
                "policies": [{"type": "csv_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
    ]
    db.record_audit_event(
        "demo.seeded",
        {
            "credential_id": credential["id"],
            "credential_version": credential.get("credential_version"),
            "secret_kek_id": credential.get("secret_kek_id"),
            "route_ids": [route["id"] for route in routes],
            "policy_hash": policy_snapshot.hash,
        },
    )
    return {"credential": credential, "routes": routes, "policy_hash": policy_snapshot.hash, "policy_path": str(POLICY_BUNDLE_PATH)}


UI_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Serverware</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8f5;
      --text: #1f2933;
      --muted: #697586;
      --line: #d7ddd5;
      --panel: #ffffff;
      --accent: #0f766e;
      --accent-2: #8b5cf6;
      --warn: #b45309;
      --bad: #b91c1c;
      --good: #166534;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 64px;
      padding: 0 24px;
      border-bottom: 1px solid var(--line);
      background: #ffffff;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 18px; }
    .mark { width: 30px; height: 30px; border-radius: 7px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); }
    .status { display: flex; gap: 12px; align-items: center; color: var(--muted); }
    .token-field { width: 220px; }
    main { display: grid; grid-template-columns: 360px minmax(0, 1fr); min-height: calc(100vh - 64px); }
    aside { border-right: 1px solid var(--line); background: #fbfcfa; padding: 18px; }
    section { padding: 18px 24px; border-bottom: 1px solid var(--line); }
    h2 { margin: 0 0 12px; font-size: 15px; }
    label { display: block; margin: 10px 0 4px; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      background: #fff;
      color: var(--text);
      font: inherit;
    }
    textarea { min-height: 84px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { flex: 1; }
    button, .button {
      border: 1px solid #0d5f59;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      padding: 8px 10px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
    }
    button.secondary, .button.secondary { background: #fff; color: var(--text); border-color: var(--line); }
    button.danger { background: var(--bad); border-color: #991b1b; }
    button:disabled { opacity: .55; cursor: not-allowed; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); }
    th, td { border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }
    th { font-size: 12px; color: var(--muted); text-transform: uppercase; background: #fbfcfa; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .pill { display: inline-flex; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 800; }
    .pill.good { background: #dcfce7; color: var(--good); }
    .pill.warn { background: #fef3c7; color: var(--warn); }
    .pill.bad { background: #fee2e2; color: var(--bad); }
    .muted { color: var(--muted); }
    .stack { display: grid; gap: 12px; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .main-grid { display: grid; grid-template-columns: minmax(0, 1fr); }
    .json { max-width: 420px; white-space: pre-wrap; overflow-wrap: anywhere; }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      aside { border-right: 0; border-bottom: 1px solid var(--line); }
      header { padding: 0 14px; }
      section { padding: 16px 14px; overflow-x: auto; }
    }
  </style>
</head>
<body>
  <header>
    <div class="brand"><div class="mark"></div><span>Serverware</span></div>
    <div class="status">
      <span id="ca-status" class="pill warn">CA pending</span>
      <input id="admin-token" class="token-field" type="password" placeholder="Admin token" autocomplete="current-password">
      <button class="secondary" onclick="refresh()">Refresh</button>
      <button class="secondary" onclick="registerPasskey()">Register passkey</button>
      <button onclick="seedDemo()">Seed demo</button>
    </div>
  </header>
  <main>
    <aside>
      <div class="stack">
        <section>
          <h2>Credential</h2>
          <form id="credential-form">
            <label>Name</label>
            <input name="name" required placeholder="Gmail OAuth token">
            <label>Kind</label>
            <select name="kind">
              <option value="bearer">Bearer</option>
              <option value="header">Header</option>
              <option value="basic">Basic</option>
              <option value="query">Query</option>
              <option value="cookie">Cookie</option>
            </select>
            <label>Secret</label>
            <textarea name="secret" required></textarea>
            <label>Metadata JSON</label>
            <textarea name="metadata">{}</textarea>
            <label></label>
            <button type="submit">Create credential</button>
          </form>
        </section>
        <section>
          <h2>Route</h2>
          <form id="route-form">
            <label>Name</label>
            <input name="name" required placeholder="Gmail recent mailbox">
            <div class="row">
              <div><label>Host</label><input name="match_host" required placeholder="gmail.googleapis.com"></div>
              <div><label>Path prefix</label><input name="match_path_prefix" value="/"></div>
            </div>
            <label>Credential</label>
            <select name="credential_id" id="route-credential"></select>
            <div class="row">
              <div><label>Injection</label><select name="injection_type">
                <option value="bearer">Bearer</option>
                <option value="header">Header</option>
                <option value="basic">Basic</option>
                <option value="query">Query</option>
                <option value="cookie">Cookie</option>
              </select></div>
              <div><label>Enabled</label><select name="enabled"><option value="true">Enabled</option><option value="false">Paused</option></select></div>
            </div>
            <label>Injection JSON</label>
            <textarea name="injection">{"type":"bearer"}</textarea>
            <label>Policies JSON</label>
            <textarea name="policies">[{"type":"gmail_recent","days":30},{"type":"approval","ttl_seconds":30}]</textarea>
            <label></label>
            <button type="submit">Create route</button>
          </form>
        </section>
      </div>
    </aside>
    <div class="main-grid">
      <section>
        <div class="toolbar">
          <h2 style="margin-right:auto">Credentials</h2>
          <button class="secondary" onclick="showCaVerifier()">CA verifier</button>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Metadata</th><th></th></tr></thead>
          <tbody id="credentials"></tbody>
        </table>
      </section>
      <section>
        <h2>Routes</h2>
        <table>
          <thead><tr><th>Name</th><th>Match</th><th>Credential</th><th>Injection</th><th>Policies</th><th></th></tr></thead>
          <tbody id="routes"></tbody>
        </table>
      </section>
      <section>
        <h2>Approvals</h2>
        <table>
          <thead><tr><th>Status</th><th>Route</th><th>Request</th><th>Until</th><th></th></tr></thead>
          <tbody id="approvals"></tbody>
        </table>
      </section>
      <section>
        <div class="toolbar">
          <h2 style="margin-right:auto">Traffic</h2>
          <button class="secondary" onclick="clearLogs()">Clear</button>
        </div>
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Route</th><th>Request</th><th>Reason</th></tr></thead>
          <tbody id="logs"></tbody>
        </table>
      </section>
    </div>
  </main>
  <script>
    let state = {credentials: [], routes: [], approvals: [], logs: [], ca_ready: false};
    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const json = (value) => esc(JSON.stringify(value, null, 2));
    const tokenKey = 'serverware.adminToken';

    function adminToken() {
      return $('admin-token').value.trim();
    }

    function adminHeaders() {
      const token = adminToken();
      return token ? {'X-Serverware-Admin-Token': token} : {};
    }

    function requireAdminToken() {
      if (adminToken()) return true;
      $('admin-token').placeholder = 'Admin token required';
      $('admin-token').focus();
      return false;
    }

    function b64ToBytes(value) {
      const padded = value + '='.repeat((4 - value.length % 4) % 4);
      const raw = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
      return Uint8Array.from(raw, (char) => char.charCodeAt(0));
    }

    function bytesToB64(value) {
      const raw = String.fromCharCode(...new Uint8Array(value));
      return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function credentialToJson(credential) {
      const response = credential.response;
      const output = {id: credential.id, rawId: bytesToB64(credential.rawId), type: credential.type, response: {}};
      for (const key of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
        if (response[key]) output.response[key] = bytesToB64(response[key]);
      }
      return output;
    }

    function prepareCreationOptions(options) {
      const publicKey = options.publicKey;
      publicKey.challenge = b64ToBytes(publicKey.challenge);
      publicKey.user.id = b64ToBytes(publicKey.user.id);
      return publicKey;
    }

    function prepareRequestOptions(options) {
      const publicKey = options.publicKey;
      publicKey.challenge = b64ToBytes(publicKey.challenge);
      publicKey.allowCredentials = (publicKey.allowCredentials || []).map((item) => ({...item, id: b64ToBytes(item.id)}));
      return publicKey;
    }

    async function api(path, options = {}) {
      if (!requireAdminToken()) throw new Error('admin token required');
      const headers = {'Content-Type': 'application/json', ...adminHeaders(), ...(options.headers || {})};
      const res = await fetch(path, {...options, headers});
      if (res.status === 401) {
        $('admin-token').value = '';
        $('admin-token').placeholder = 'Admin token rejected';
        localStorage.removeItem(tokenKey);
      }
      if (!res.ok) throw new Error(await res.text());
      if (res.status === 204) return null;
      return res.json();
    }

    async function refresh() {
      if (!adminToken()) {
        render();
        return;
      }
      try {
        state = await api('/api/bootstrap');
        render();
      } catch (error) {
        console.warn(error.message);
      }
    }

    function credentialName(id) {
      return (state.credentials.find((item) => item.id === id) || {}).name || 'None';
    }

    function routeName(id) {
      return (state.routes.find((item) => item.id === id) || {}).name || id || 'None';
    }

    function pill(status) {
      const cls = status === 'approved' || status === 'allowed' || status === 'response' ? 'good' : status === 'pending' || status === 'blocked' ? 'warn' : 'bad';
      return `<span class="pill ${cls}">${esc(status)}</span>`;
    }

    function render() {
      $('ca-status').textContent = state.ca_ready ? 'CA ready' : 'CA pending';
      $('ca-status').className = state.ca_ready ? 'pill good' : 'pill warn';
      $('route-credential').innerHTML = '<option value="">None</option>' + state.credentials.map((item) => `<option value="${esc(item.id)}">${esc(item.name)}</option>`).join('');
      $('credentials').innerHTML = state.credentials.map((item) => `
        <tr>
          <td><strong>${esc(item.name)}</strong><br><code>${esc(item.id)}</code></td>
          <td>${esc(item.kind)}</td>
          <td><code class="json">${json(item.metadata)}</code></td>
          <td><button class="danger" onclick="deleteCredential('${item.id}')">Delete</button></td>
        </tr>`).join('') || '<tr><td colspan="4" class="muted">No credentials</td></tr>';

      $('routes').innerHTML = state.routes.map((item) => `
        <tr>
          <td>${item.enabled ? pill('enabled') : pill('paused')}<br><strong>${esc(item.name)}</strong><br><code>${esc(item.id)}</code></td>
          <td><code>${esc(item.match_host)}${esc(item.match_path_prefix)}</code></td>
          <td>${esc(credentialName(item.credential_id))}</td>
          <td><code class="json">${json(item.injection)}</code></td>
          <td><code class="json">${json(item.policies)}</code></td>
          <td><button class="danger" onclick="deleteRoute('${item.id}')">Delete</button></td>
        </tr>`).join('') || '<tr><td colspan="6" class="muted">No routes</td></tr>';

      $('approvals').innerHTML = state.approvals.map((item) => `
        <tr>
          <td>${pill(item.status)}</td>
          <td>${esc(routeName(item.route_id))}</td>
          <td><strong>${esc(item.method)}</strong><br><code>${esc(item.url)}</code></td>
          <td><code>${esc(item.approved_until || item.expires_at)}</code></td>
          <td>${item.status === 'pending' ? `<div class="row"><input id="ttl-${item.id}" value="30" inputmode="numeric"><button onclick="approve('${item.id}')">Approve</button><button class="danger" onclick="deny('${item.id}')">Deny</button></div>` : ''}</td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">No approvals</td></tr>';

      $('logs').innerHTML = state.logs.map((item) => `
        <tr>
          <td><code>${esc(item.created_at)}</code></td>
          <td>${pill(item.action)}</td>
          <td>${esc(item.status_code || '')}</td>
          <td>${esc(routeName(item.route_id))}</td>
          <td><strong>${esc(item.method)}</strong><br><code>${esc(item.url)}</code></td>
          <td>${esc(item.reason || '')}</td>
        </tr>`).join('') || '<tr><td colspan="6" class="muted">No traffic</td></tr>';
    }

    $('credential-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.target);
      await api('/api/credentials', {method: 'POST', body: JSON.stringify({
        name: form.get('name'),
        kind: form.get('kind'),
        secret: form.get('secret'),
        metadata: JSON.parse(form.get('metadata') || '{}')
      })});
      event.target.reset();
      event.target.metadata.value = '{}';
      await refresh();
    });

    $('route-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.target);
      const injection = JSON.parse(form.get('injection') || '{}');
      injection.type = form.get('injection_type') || injection.type || 'bearer';
      await api('/api/routes', {method: 'POST', body: JSON.stringify({
        name: form.get('name'),
        enabled: form.get('enabled') === 'true',
        match_host: form.get('match_host'),
        match_path_prefix: form.get('match_path_prefix') || '/',
        credential_id: form.get('credential_id') || null,
        injection,
        policies: JSON.parse(form.get('policies') || '[]')
      })});
      event.target.reset();
      event.target.match_path_prefix.value = '/';
      event.target.injection.value = '{"type":"bearer"}';
      event.target.policies.value = '[{"type":"gmail_recent","days":30},{"type":"approval","ttl_seconds":30}]';
      await refresh();
    });

    async function deleteCredential(id) { await api(`/api/credentials/${id}`, {method: 'DELETE'}); await refresh(); }
    async function deleteRoute(id) { await api(`/api/routes/${id}`, {method: 'DELETE'}); await refresh(); }
    async function approve(id) {
      const options = await api(`/api/approvals/${id}/webauthn/options`, {method: 'POST'});
      let body = {};
      if (window.PublicKeyCredential && (options.publicKey.allowCredentials || []).length) {
        const assertion = await navigator.credentials.get({publicKey: prepareRequestOptions(options)});
        body.assertion = credentialToJson(assertion);
      }
      await api(`/api/approvals/${id}/approve?ttl_seconds=${encodeURIComponent($('ttl-' + id).value || '30')}`, {
        method: 'POST',
        body: JSON.stringify(body)
      });
      await refresh();
    }
    async function deny(id) { await api(`/api/approvals/${id}/deny`, {method: 'POST'}); await refresh(); }
    async function seedDemo() { await api('/api/demo/seed', {method: 'POST'}); await refresh(); }
    async function clearLogs() { await api('/api/logs', {method: 'DELETE'}); await refresh(); }
    async function registerPasskey() {
      if (!window.PublicKeyCredential) throw new Error('WebAuthn is not available in this browser');
      const options = await api('/api/webauthn/register/options', {method: 'POST', body: JSON.stringify({label: 'YubiKey'})});
      const credential = await navigator.credentials.create({publicKey: prepareCreationOptions(options)});
      await api('/api/webauthn/register/verify', {
        method: 'POST',
        body: JSON.stringify({label: 'YubiKey', response: credentialToJson(credential)})
      });
      await refresh();
    }
    async function showCaVerifier() {
      const command = 'make install-ca\nexport HTTPS_PROXY=http://localhost:8080\nexport HTTP_PROXY=http://localhost:8080\ncurl --proxy "$HTTPS_PROXY" --cacert .tmp/serverware-ca.pem -H "X-Serverware-Agent: demo-agent" https://demo-upstream:8443/echo';
      try { await navigator.clipboard.writeText(command); } catch (_) {}
      alert(command);
    }
    $('admin-token').value = localStorage.getItem(tokenKey) || '';
    $('admin-token').addEventListener('change', () => {
      localStorage.setItem(tokenKey, adminToken());
      refresh();
    });
    refresh();
    setInterval(refresh, 4000);
  </script>
</body>
</html>
"""
