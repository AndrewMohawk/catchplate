from __future__ import annotations

import hmac
import html
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from serverware import __version__
from serverware.attestation import (
    attestation_document,
    image_signatures_digest,
    image_signatures_document,
    release_provenance_digest,
    release_provenance_document,
    runtime_manifest_digest,
    source_tree_digest,
)
from serverware.config import (
    CONTROL_PLANE_TWO_PERSON_ACTIONS,
    CONTROL_PLANE_TWO_PERSON_REQUIRED,
    CONTROL_PLANE_TWO_PERSON_TTL_SECONDS,
    CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES,
    CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION,
    CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
    CA_INSTALL_SESSIONS_PATH,
    CA_INSTALL_SESSION_TTL_SECONDS,
    DATA_PLANE_AUDIT_TOKEN,
    DIRECT_CA_DOWNLOAD_ENABLED,
    MITMPROXY_CONF_DIR,
    POLICY_BUNDLE_PATH,
    POLICY_CANARY_BUNDLE_PATH,
    POLICY_CANARY_MAX_DENIALS,
    POLICY_CANARY_MIN_AUDIT_EVENTS,
    POLICY_CANARY_MIN_OBSERVATION_SECONDS,
    POLICY_CANARY_REQUIRED,
    POLICY_CANARY_STATE_PATH,
    POLICY_PUBLISH_DRY_RUN_REQUIRED,
    RBAC_BINDINGS_PATH,
)
from serverware import db, grants, runtime
from serverware.auth import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, AdminIdentity, admin_status, issue_csrf_cookie, require_admin, require_role, rotate_generated_admin_token, validate_csrf_request
from serverware.enrollment import AgentEnrollmentError, build_agent_enrollment
from serverware.key_release import KeyReleaseError, release_material, status as key_release_status
from serverware.oauth import OAuthError, create_authorization_url, exchange_authorization_code, provider_status
from serverware.policy_bundle import (
    PolicyBundleError,
    compile_policy_bundle,
    demo_policy_bundle,
    get_policy_snapshot,
    policy_hash,
    policy_public_key_hash,
    policy_public_key_pem,
    sign_policy_bundle,
    write_policy_bundle,
)
from serverware.response_identity import response_signature_headers, response_statement
from serverware.webauthn import (
    WebAuthnError,
    approval_options,
    control_plane_mutation_options,
    create_dev_credential,
    dev_assertion,
    registration_options,
    verify_control_plane_mutation_assertion,
    verify_approval_assertion,
    verify_registration,
)
from serverware.webauthn_trust import WebAuthnTrustError, status as webauthn_trust_status, write_trust_bundle


app = FastAPI(title="Serverware", version=__version__)


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    try:
        validate_csrf_request(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
    return await call_next(request)


@app.middleware("http")
async def signed_response_middleware(request: Request, call_next):
    response = await call_next(request)
    body = b""
    async for chunk in response.body_iterator:
        body += chunk
    snapshot = get_policy_snapshot()
    statement = response_statement(
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        status_code=response.status_code,
        body=body,
        nonce=request.headers.get("X-Serverware-Response-Nonce"),
        context={
            "runtime_manifest_digest": runtime_manifest_digest(),
            "policy_bundle_digest": snapshot.hash if snapshot else None,
            "provenance_digest": release_provenance_digest(),
            "image_signatures_digest": image_signatures_digest(),
            "source_tree_digest": source_tree_digest(),
        },
    )
    headers = dict(response.headers)
    headers.pop("content-length", None)
    headers.update(response_signature_headers(statement))
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
        background=response.background,
    )


class CredentialCreate(BaseModel):
    name: str
    kind: str = "bearer"
    secret: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    mfa: dict[str, Any] | None = None


class CredentialUpdate(BaseModel):
    name: str | None = None
    kind: str | None = None
    secret: str | None = None
    metadata: dict[str, Any] | None = None
    mfa: dict[str, Any] | None = None


class OAuthStartRequest(BaseModel):
    provider: str = Field(min_length=1)
    credential_name: str | None = Field(default=None, alias="credentialName")
    scopes: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    mfa: dict[str, Any] | None = None


class RouteCreate(BaseModel):
    name: str
    enabled: bool = True
    match_host: str
    match_path_prefix: str = "/"
    credential_id: str | None = None
    injection: dict[str, Any] = Field(default_factory=lambda: {"type": "bearer"})
    policies: list[dict[str, Any]] = Field(default_factory=list)
    mfa: dict[str, Any] | None = None


class RouteUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    match_host: str | None = None
    match_path_prefix: str | None = None
    credential_id: str | None = None
    injection: dict[str, Any] | None = None
    policies: list[dict[str, Any]] | None = None
    mfa: dict[str, Any] | None = None


class ApprovalApprove(BaseModel):
    note: str | None = None
    assertion: dict[str, Any] | None = None


class ApprovalDeny(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class BreakGlassGrantRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_id: str = Field(alias="principalId", min_length=1)
    route_id: str = Field(alias="routeId", min_length=1)
    credential_id: str = Field(alias="credentialId", min_length=1)
    credential_version: int = Field(alias="credentialVersion", ge=1)
    policy_hash: str = Field(alias="policyHash", min_length=1)
    request_digest: str = Field(alias="requestDigest", min_length=1)
    operation_digest: str | None = Field(default=None, alias="operationDigest")
    method: str = Field(default="BREAK-GLASS", min_length=1)
    url: str = Field(default="serverware://break-glass")
    grant_ttl_seconds: int = Field(default=300, alias="grantTtlSeconds", ge=1, le=3600)
    grant_max_uses: int = Field(default=1, alias="grantMaxUses", ge=1, le=5)
    reason: str = Field(min_length=1, max_length=2000)
    canonical_request: dict[str, Any] = Field(default_factory=dict, alias="canonicalRequest")
    redacted_display: dict[str, Any] = Field(default_factory=dict, alias="redactedDisplay")
    mfa: dict[str, Any] | None = None


class ControlPlaneMutationMfa(BaseModel):
    mfa: dict[str, Any] | None = None


class ControlPlaneApprovalDecision(BaseModel):
    note: str | None = None
    mfa: dict[str, Any] | None = None


class ControlPlaneMutationWebAuthnOptions(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    action: str = Field(min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, alias="resourceId")
    payload_digest: str = Field(alias="payloadDigest", min_length=71, max_length=71)


class PolicyDryRunCase(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    principal_id: str = Field(alias="principalId", min_length=1)
    scheme: str = "https"
    host: str = Field(min_length=1)
    port: int = Field(default=443, ge=1, le=65535)
    method: str = Field(min_length=1)
    path: str = Field(min_length=1)
    expect: str = Field(default="allow", pattern="^(allow|deny)$")


class PolicyCandidateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    bundle: dict[str, Any]
    dry_run: list[PolicyDryRunCase] = Field(default_factory=list, alias="dryRun")


class PolicyPublishRequest(PolicyCandidateRequest):
    activation_mode: str = Field(default="full", alias="activationMode", pattern="^(full|canary)$")
    canary_percent: float = Field(default=5.0, alias="canaryPercent", ge=0.1, le=100.0)
    mfa: dict[str, Any] | None = None


class PolicyCanaryActivationRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    canary_id: str = Field(alias="canaryId", min_length=1)
    min_observation_seconds: int | None = Field(default=None, alias="minObservationSeconds", ge=0)
    min_audit_events: int | None = Field(default=None, alias="minAuditEvents", ge=0)
    max_denials: int | None = Field(default=None, alias="maxDenials", ge=0)
    mfa: dict[str, Any] | None = None


class PolicyCanaryCancelRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    canary_id: str = Field(alias="canaryId", min_length=1)
    note: str | None = Field(default=None, max_length=500)


class RoleBindingUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    roles: list[str] = Field(min_length=1)
    reason: str | None = Field(default=None, max_length=500)
    mfa: dict[str, Any] | None = None


class DeprovisionSubjectRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    subject_id: str = Field(alias="subjectId", min_length=1)
    reason: str | None = Field(default=None, max_length=500)
    mfa: dict[str, Any] | None = None


class AdminTokenRotateRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
    mfa: dict[str, Any] | None = None


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
    method: str = Field(default="UNKNOWN", min_length=1)
    url: str = Field(default="serverware://data-plane/jit", min_length=1)
    canonical_request: dict[str, Any] = Field(default_factory=dict, alias="canonicalRequest")
    redacted_display: dict[str, Any] = Field(default_factory=dict, alias="redactedDisplay")


class DataPlaneRateLimitConsume(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    counter_key: str = Field(alias="counterKey", min_length=71, max_length=71)
    principal_id: str = Field(alias="principalId", min_length=1)
    route_id: str = Field(alias="routeId", min_length=1)
    credential_ref: str | None = Field(default=None, alias="credentialRef")
    credential_version: int = Field(alias="credentialVersion", ge=0)
    policy_hash: str = Field(alias="policyHash", min_length=1)
    constraint_id: str = Field(alias="constraintId", min_length=1)
    operation: str | None = None
    max_count: int = Field(alias="max", ge=1)
    window_seconds: int = Field(alias="windowSeconds", ge=1)
    consume: bool = True
    actor_id: str = Field(default="decision-gate-rs", alias="actorId", min_length=1, max_length=128)


class AgentEnrollmentCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_id: str = Field(alias="principalId", min_length=1)
    proxy_url: str = Field(alias="proxyUrl", min_length=1)
    control_plane_url: str = Field(alias="controlPlaneUrl", min_length=1)
    proxy_egress_cidrs: list[str] = Field(alias="proxyEgressCidrs", min_length=1)
    namespace: str = "serverware-agents"
    pod_selector: dict[str, str] = Field(default_factory=dict, alias="podSelector")
    ca_mount_path: str = Field(default="/etc/serverware/serverware-ca.pem", alias="caMountPath")


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
    route = _active_route_by_id(str(approval.get("route_id") or ""))
    return route.jit or {}


def _active_route_by_id(route_id: str) -> Any:
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    route = next((item for item in snapshot.routes if item.id == route_id), None)
    if not route:
        raise HTTPException(status_code=409, detail="approval route is not in the active policy")
    return route


def _approval_authn_policy(jit: dict[str, Any]) -> dict[str, Any]:
    return ((jit.get("approvers") or {}).get("authn") or {})


def _assert_approver_allowed(identity: AdminIdentity, jit: dict[str, Any]) -> None:
    approvers = jit.get("approvers") or {}
    users = set(approvers.get("users") or [])
    if users and "*" not in users and identity.user_id not in users:
        raise HTTPException(status_code=403, detail="current user is not an allowed approver for this route")


def _webauthn_required(authn_policy: dict[str, Any]) -> bool:
    return bool(authn_policy.get("webauthnRequired"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _control_plane_payload_digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _control_plane_mutation_authn_policy() -> dict[str, Any]:
    policy: dict[str, Any] = {"userVerification": "required"}
    if CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES:
        policy["allowedAuthenticatorClasses"] = list(CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES)
    if CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION:
        policy["requireHardwareAttestation"] = True
    return policy


def _require_control_plane_mutation_mfa(
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    mfa: dict[str, Any] | None,
    identity: AdminIdentity,
) -> dict[str, Any] | None:
    if not CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED:
        return None
    assertion = (mfa or {}).get("assertion") if isinstance(mfa, dict) else None
    if not assertion:
        raise HTTPException(status_code=412, detail="WebAuthn assertion required for control-plane mutation")
    try:
        return verify_control_plane_mutation_assertion(
            user_id=identity.user_id,
            action=action,
            resource_id=resource_id,
            payload_digest=payload_digest,
            authn_policy=_control_plane_mutation_authn_policy(),
            assertion=assertion,
        )
    except WebAuthnError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _control_plane_two_person_required(action: str) -> bool:
    if not CONTROL_PLANE_TWO_PERSON_REQUIRED:
        return False
    configured = set(CONTROL_PLANE_TWO_PERSON_ACTIONS)
    return "*" in configured or action in configured


def _control_plane_approval_id(mfa: dict[str, Any] | None) -> str | None:
    if not isinstance(mfa, dict):
        return None
    value = mfa.get("approvalId") or mfa.get("approval_id") or mfa.get("controlPlaneApprovalId")
    return str(value) if value else None


def _control_plane_approval_roles(action: str) -> set[str]:
    if action.startswith("policy."):
        return {"policy_publisher"}
    if action.startswith("credential."):
        return {"credential_owner"}
    if action.startswith("route."):
        return {"policy_author"}
    return {"admin"}


def _assert_control_plane_approval_role(identity: AdminIdentity, action: str) -> None:
    required = _control_plane_approval_roles(action)
    if not identity.has_any_role(required):
        raise HTTPException(status_code=403, detail=f"required role: {' or '.join(sorted(required))}")


def _require_control_plane_two_person(
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    mfa: dict[str, Any] | None,
    identity: AdminIdentity,
    request: dict[str, Any],
) -> dict[str, Any] | None:
    if not _control_plane_two_person_required(action):
        return None
    approval_id = _control_plane_approval_id(mfa)
    if approval_id:
        result = db.consume_control_plane_approval(
            approval_id,
            action=action,
            resource_id=resource_id,
            payload_digest=payload_digest,
            actor_id=identity.user_id,
        )
        if not result.get("ok"):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "control_plane_approval_not_usable",
                    "reason": result.get("reason"),
                    "approvalId": approval_id,
                },
            )
        approval = result["approval"]
        return {
            "required": True,
            "approval_id": approval["id"],
            "approved_by": approval.get("approved_by"),
            "approved_at": approval.get("approved_at"),
            "payload_digest": payload_digest,
        }
    approval = db.ensure_control_plane_approval(
        action=action,
        resource_id=resource_id,
        payload_digest=payload_digest,
        requester_id=identity.user_id,
        request=request,
        ttl_seconds=CONTROL_PLANE_TWO_PERSON_TTL_SECONDS,
    )
    raise HTTPException(
        status_code=428,
        detail={
            "error": "control_plane_approval_required",
            "approvalId": approval["id"],
            "status": approval["status"],
            "action": action,
            "resourceId": resource_id,
            "payloadDigest": payload_digest,
            "expiresAt": approval["expires_at"],
            "retry": {"mfa.approvalId": approval["id"]},
        },
    )


def _policy_ids(raw: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in raw.get(key) or [] if isinstance(item, dict) and item.get("id")}


def _policy_diff(previous: dict[str, Any] | None, candidate: dict[str, Any]) -> dict[str, Any]:
    previous = previous or {}
    diff: dict[str, Any] = {}
    for key in ("principals", "credentials", "routes"):
        old = _policy_ids(previous, key)
        new = _policy_ids(candidate, key)
        changed = [
            item_id
            for item_id in sorted(set(old).intersection(new))
            if _canonical_json(old[item_id]) != _canonical_json(new[item_id])
        ]
        diff[key] = {
            "added": sorted(set(new) - set(old)),
            "removed": sorted(set(old) - set(new)),
            "changed": changed,
        }
    old_meta = previous.get("metadata") if isinstance(previous.get("metadata"), dict) else {}
    new_meta = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    diff["metadata"] = {
        "previousSequence": old_meta.get("sequence"),
        "newSequence": new_meta.get("sequence"),
        "previousRollbackEpoch": old_meta.get("rollbackEpoch"),
        "newRollbackEpoch": new_meta.get("rollbackEpoch"),
    }
    return diff


def _policy_metadata_int(raw: dict[str, Any], key: str) -> int:
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    try:
        return int(metadata.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _assert_policy_publish_monotonic(current: dict[str, Any] | None, candidate: dict[str, Any]) -> None:
    if not current:
        return
    current_sequence = _policy_metadata_int(current, "sequence")
    candidate_sequence = _policy_metadata_int(candidate, "sequence")
    current_epoch = _policy_metadata_int(current, "rollbackEpoch")
    candidate_epoch = _policy_metadata_int(candidate, "rollbackEpoch")
    if candidate_epoch < current_epoch:
        raise HTTPException(status_code=409, detail="policy rollbackEpoch cannot decrease")
    if candidate_sequence <= current_sequence:
        raise HTTPException(status_code=409, detail="policy sequence must increase monotonically")


def _run_policy_dry_runs(snapshot: Any, cases: list[PolicyDryRunCase]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        principal = snapshot.principals.get(case.principal_id)
        decision = "deny"
        route_id = None
        reason = "principal_not_found"
        if principal:
            matched = snapshot.match_route(
                case.scheme.lower(),
                case.host,
                case.port,
                case.method,
                case.path,
                case.principal_id,
            )
            if matched:
                decision = "allow"
                route_id = matched.route.id
                reason = "route_matched"
            else:
                reason = "route_not_matched"
        passed = decision == case.expect
        results.append(
            {
                "index": index,
                "name": case.name,
                "principalId": case.principal_id,
                "method": case.method.upper(),
                "host": case.host,
                "path": case.path,
                "expect": case.expect,
                "decision": decision,
                "routeId": route_id,
                "reason": reason,
                "passed": passed,
            }
        )
    return {
        "required": POLICY_PUBLISH_DRY_RUN_REQUIRED,
        "count": len(results),
        "passed": all(item["passed"] for item in results),
        "results": results,
    }


def _policy_candidate_report(
    *,
    bundle: dict[str, Any],
    dry_run: list[PolicyDryRunCase],
    enforce_monotonic: bool,
) -> dict[str, Any]:
    current = get_policy_snapshot()
    current_raw = current.raw if current else None
    try:
        signed = sign_policy_bundle(bundle)
        candidate = compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    except PolicyBundleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if enforce_monotonic:
        _assert_policy_publish_monotonic(current_raw, signed)
    dry_run_result = _run_policy_dry_runs(candidate, dry_run)
    if POLICY_PUBLISH_DRY_RUN_REQUIRED and not dry_run:
        raise HTTPException(status_code=412, detail="policy publish requires dry-run decision tests")
    if not dry_run_result["passed"]:
        raise HTTPException(status_code=409, detail={"error": "policy dry-run failed", "dryRun": dry_run_result})
    metadata = signed.get("metadata") if isinstance(signed.get("metadata"), dict) else {}
    current_metadata = current_raw.get("metadata") if isinstance(current_raw, dict) and isinstance(current_raw.get("metadata"), dict) else {}
    return {
        "ok": True,
        "candidate": {
            "policyHash": candidate.hash,
            "signingKeyId": metadata.get("signingKeyId"),
            "signature": metadata.get("signature"),
            "sequence": metadata.get("sequence"),
            "rollbackEpoch": metadata.get("rollbackEpoch"),
            "routes": len(candidate.routes),
            "principals": len(candidate.principals),
            "credentials": len(candidate.credentials),
        },
        "current": {
            "policyHash": current.hash if current else None,
            "sequence": current_metadata.get("sequence"),
            "rollbackEpoch": current_metadata.get("rollbackEpoch"),
        },
        "diff": _policy_diff(current_raw, signed),
        "dryRun": dry_run_result,
        "signedBundle": signed,
    }


def _policy_publish_payload_digest(payload: PolicyPublishRequest) -> str:
    return _control_plane_payload_digest(
        {
            "bundle": payload.bundle,
            "dryRun": [case.model_dump(by_alias=True) for case in payload.dry_run],
            "activationMode": payload.activation_mode,
            "canaryPercent": payload.canary_percent,
        }
    )


def _policy_canary_activate_payload_digest(payload: PolicyCanaryActivationRequest) -> str:
    return _control_plane_payload_digest(
        {
            "canaryId": payload.canary_id,
            "minObservationSeconds": payload.min_observation_seconds,
            "minAuditEvents": payload.min_audit_events,
            "maxDenials": payload.max_denials,
        }
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ca_cert_path() -> Path:
    return MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"


def _ca_file_response(*, headers: dict[str, str]) -> FileResponse:
    ca_path = _ca_cert_path()
    if not ca_path.exists():
        raise HTTPException(status_code=404, detail="mitmproxy CA has not been generated yet")
    response_headers = {
        "Cache-Control": "no-store",
        "X-Serverware-Install-Path": "verifier-mediated-attestation",
    }
    response_headers.update(headers)
    return FileResponse(
        ca_path,
        media_type="application/x-pem-file",
        filename="serverware-ca.pem",
        headers=response_headers,
    )


def _read_ca_install_sessions() -> dict[str, Any]:
    if not CA_INSTALL_SESSIONS_PATH.exists():
        return {"version": "serverware.caInstallSessions/v1", "sessions": {}}
    try:
        state = json.loads(CA_INSTALL_SESSIONS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="CA install session state is unreadable") from exc
    if not isinstance(state, dict) or not isinstance(state.get("sessions"), dict):
        raise HTTPException(status_code=503, detail="CA install session state is invalid")
    return state


def _write_ca_install_sessions(state: dict[str, Any]) -> None:
    CA_INSTALL_SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CA_INSTALL_SESSIONS_PATH.with_suffix(CA_INSTALL_SESSIONS_PATH.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    temporary.replace(CA_INSTALL_SESSIONS_PATH)


def _ca_install_session_public(session: dict[str, Any], *, include_token: str | None = None) -> dict[str, Any]:
    result = {
        "id": session.get("id"),
        "nonce": session.get("nonce"),
        "status": session.get("status"),
        "createdAt": session.get("created_at"),
        "expiresAt": session.get("expires_at"),
        "consumedAt": session.get("consumed_at"),
        "downloadUrl": f"/api/ca/install-sessions/{session.get('id')}/ca.pem",
        "tokenHeader": "X-Serverware-CA-Install-Token",
        "installMethod": "verifier-mediated-attestation",
    }
    if include_token is not None:
        result["token"] = include_token
    return result


def _read_policy_canary_state() -> dict[str, Any] | None:
    if not POLICY_CANARY_STATE_PATH.exists():
        return None
    try:
        state = json.loads(POLICY_CANARY_STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="policy canary state is unreadable") from exc
    if not isinstance(state, dict):
        raise HTTPException(status_code=503, detail="policy canary state is invalid")
    return state


def _write_policy_canary_state(state: dict[str, Any]) -> None:
    POLICY_CANARY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_CANARY_STATE_PATH.with_suffix(POLICY_CANARY_STATE_PATH.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    temporary.replace(POLICY_CANARY_STATE_PATH)


def _write_policy_canary_bundle(signed_bundle: dict[str, Any]) -> None:
    POLICY_CANARY_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_CANARY_BUNDLE_PATH.with_suffix(POLICY_CANARY_BUNDLE_PATH.suffix + ".tmp")
    temporary.write_text(json.dumps(signed_bundle, indent=2, sort_keys=True) + "\n")
    temporary.replace(POLICY_CANARY_BUNDLE_PATH)


def _policy_canary_id(policy_hash_value: str, sequence: Any) -> str:
    digest = str(policy_hash_value).removeprefix("sha256:")[:16] or "unknown"
    return f"policy-canary-{sequence}-{digest}"


def _policy_canary_public(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": state.get("id"),
        "status": state.get("status"),
        "policyId": state.get("policy_id"),
        "previousPolicyHash": state.get("previous_policy_hash"),
        "candidatePolicyHash": state.get("candidate_policy_hash"),
        "candidateSequence": state.get("candidate_sequence"),
        "candidateRollbackEpoch": state.get("candidate_rollback_epoch"),
        "startedAt": state.get("started_at"),
        "startedBy": state.get("started_by"),
        "activatedAt": state.get("activated_at"),
        "activatedBy": state.get("activated_by"),
        "cancelledAt": state.get("cancelled_at"),
        "cancelledBy": state.get("cancelled_by"),
        "canaryPercent": state.get("canary_percent"),
        "bundlePath": state.get("bundle_path"),
        "diff": state.get("diff"),
        "dryRun": state.get("dry_run"),
    }


def _audit_event_route_id(event: dict[str, Any]) -> str | None:
    for key in ("route_id", "routeId", "route"):
        value = event.get(key)
        if value:
            return str(value)
    request = event.get("request") if isinstance(event.get("request"), dict) else {}
    for key in ("route_id", "routeId", "route"):
        value = request.get(key)
        if value:
            return str(value)
    return None


def _audit_event_decision(event_type: str, event: dict[str, Any]) -> str:
    for key in ("decision", "result", "action"):
        value = event.get(key)
        if value:
            return str(value).lower()
    if "denied" in event_type or "deny" in event_type:
        return "deny"
    return ""


def _audit_event_latency(event: dict[str, Any]) -> float | None:
    for key in ("latency_ms", "latencyMs", "duration_ms", "durationMs", "upstream_latency_ms", "upstreamLatencyMs"):
        value = event.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    return None


def _policy_canary_route_filter(state: dict[str, Any]) -> set[str]:
    diff = state.get("diff") if isinstance(state.get("diff"), dict) else {}
    routes = diff.get("routes") if isinstance(diff.get("routes"), dict) else {}
    route_ids: set[str] = set()
    for key in ("added", "changed", "removed"):
        route_ids.update(str(item) for item in routes.get(key) or [])
    return route_ids


def _policy_canary_monitor(state: dict[str, Any], *, limit: int = 1000) -> dict[str, Any]:
    started_at = _parse_iso_datetime(state.get("started_at")) or datetime.now(timezone.utc)
    route_filter = _policy_canary_route_filter(state)
    events = db.list_audit_events(limit=limit)
    matched = 0
    denials = 0
    latencies: list[float] = []
    newest_event_at: str | None = None
    for item in events:
        created = _parse_iso_datetime(item.get("created_at"))
        if created and created < started_at:
            continue
        event = item.get("event") if isinstance(item.get("event"), dict) else {}
        event_type = str(item.get("event_type") or "")
        if event_type.startswith("policy.canary."):
            continue
        route_id = _audit_event_route_id(event)
        if route_filter and route_id and route_id not in route_filter:
            continue
        if route_filter and not route_id and event_type.startswith("request."):
            continue
        matched += 1
        newest_event_at = newest_event_at or item.get("created_at")
        decision = _audit_event_decision(event_type, event)
        if decision in {"deny", "denied", "block", "blocked", "reject", "rejected"}:
            denials += 1
        latency = _audit_event_latency(event)
        if latency is not None:
            latencies.append(latency)
    sorted_latencies = sorted(latencies)
    p95 = None
    if sorted_latencies:
        p95 = sorted_latencies[(len(sorted_latencies) - 1) * 95 // 100]
    return {
        "startedAt": state.get("started_at"),
        "newestEventAt": newest_event_at,
        "observationSeconds": max(0, int((datetime.now(timezone.utc) - started_at).total_seconds())),
        "routeFilter": sorted(route_filter),
        "auditEvents": matched,
        "denials": denials,
        "latencySamples": len(sorted_latencies),
        "latencyMsP95": p95,
        "complete": len(events) < limit,
    }


def _start_policy_canary(
    *,
    report: dict[str, Any],
    payload: PolicyPublishRequest,
    payload_digest: str,
    identity: AdminIdentity,
    mfa: dict[str, Any] | None,
    two_person: dict[str, Any] | None,
) -> dict[str, Any]:
    existing = _read_policy_canary_state()
    if existing and existing.get("status") == "running":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_canary_already_running",
                "canaryId": existing.get("id"),
                "candidatePolicyHash": existing.get("candidate_policy_hash"),
            },
        )
    signed_bundle = report["signedBundle"]
    metadata = signed_bundle.get("metadata") if isinstance(signed_bundle.get("metadata"), dict) else {}
    canary_id = _policy_canary_id(report["candidate"]["policyHash"], metadata.get("sequence"))
    started_at = _now_iso()
    _write_policy_canary_bundle(signed_bundle)
    state = {
        "version": "serverware.policyCanary/v1",
        "id": canary_id,
        "status": "running",
        "policy_id": metadata.get("id"),
        "previous_policy_hash": report["current"]["policyHash"],
        "candidate_policy_hash": report["candidate"]["policyHash"],
        "candidate_sequence": metadata.get("sequence"),
        "candidate_rollback_epoch": metadata.get("rollbackEpoch"),
        "started_at": started_at,
        "started_by": identity.user_id,
        "canary_percent": payload.canary_percent,
        "bundle_path": str(POLICY_CANARY_BUNDLE_PATH),
        "diff": report["diff"],
        "dry_run": report["dryRun"],
        "payload_digest": payload_digest,
        "signed_bundle": signed_bundle,
        "control_plane_mfa": mfa,
        "control_plane_approval": two_person,
    }
    _write_policy_canary_state(state)
    db.record_audit_event(
        "policy.canary.started",
        {
            "canary_id": canary_id,
            "policy_id": metadata.get("id"),
            "previous_policy_hash": report["current"]["policyHash"],
            "candidate_policy_hash": report["candidate"]["policyHash"],
            "candidate_sequence": metadata.get("sequence"),
            "candidate_rollback_epoch": metadata.get("rollbackEpoch"),
            "canary_percent": payload.canary_percent,
            "canary_bundle_path": str(POLICY_CANARY_BUNDLE_PATH),
            "diff": report["diff"],
            "dry_run": report["dryRun"],
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    response = dict(report)
    response.pop("signedBundle", None)
    response["published"] = False
    response["canary"] = _policy_canary_public(state)
    response["policyHash"] = report["current"]["policyHash"]
    return response


def _require_policy_canary_activation_thresholds(
    state: dict[str, Any],
    monitor: dict[str, Any],
    payload: PolicyCanaryActivationRequest,
) -> dict[str, int]:
    required_observation = max(POLICY_CANARY_MIN_OBSERVATION_SECONDS, payload.min_observation_seconds or 0)
    required_events = max(POLICY_CANARY_MIN_AUDIT_EVENTS, payload.min_audit_events or 0)
    max_denials = min(POLICY_CANARY_MAX_DENIALS, payload.max_denials) if payload.max_denials is not None else POLICY_CANARY_MAX_DENIALS
    if monitor["observationSeconds"] < required_observation:
        raise HTTPException(
            status_code=412,
            detail={
                "error": "policy_canary_observation_window_incomplete",
                "canaryId": state.get("id"),
                "requiredSeconds": required_observation,
                "observedSeconds": monitor["observationSeconds"],
            },
        )
    if monitor["auditEvents"] < required_events:
        raise HTTPException(
            status_code=412,
            detail={
                "error": "policy_canary_audit_evidence_incomplete",
                "canaryId": state.get("id"),
                "requiredAuditEvents": required_events,
                "observedAuditEvents": monitor["auditEvents"],
            },
        )
    if monitor["denials"] > max_denials:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "policy_canary_denial_threshold_exceeded",
                "canaryId": state.get("id"),
                "maxDenials": max_denials,
                "observedDenials": monitor["denials"],
            },
        )
    return {
        "requiredObservationSeconds": required_observation,
        "requiredAuditEvents": required_events,
        "maxDenials": max_denials,
    }


VALID_RBAC_ROLES = {"admin", "policy_author", "policy_publisher", "credential_owner", "approver", "auditor"}


def _read_rbac_bindings() -> dict[str, Any]:
    if not RBAC_BINDINGS_PATH.exists():
        return {"version": "serverware.rbacBindings/v1", "subjects": {}}
    try:
        data = json.loads(RBAC_BINDINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="RBAC binding state is unreadable") from exc
    if not isinstance(data, dict) or not isinstance(data.get("subjects"), dict):
        raise HTTPException(status_code=503, detail="RBAC binding state is invalid")
    return data


def _write_rbac_bindings(data: dict[str, Any]) -> None:
    RBAC_BINDINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = RBAC_BINDINGS_PATH.with_suffix(RBAC_BINDINGS_PATH.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(RBAC_BINDINGS_PATH)


def _normalized_rbac_roles(roles: list[str]) -> list[str]:
    normalized = sorted({str(role).strip() for role in roles if str(role).strip()})
    invalid = sorted(set(normalized) - VALID_RBAC_ROLES)
    if invalid:
        raise HTTPException(status_code=400, detail={"error": "invalid_rbac_roles", "roles": invalid})
    if not normalized:
        raise HTTPException(status_code=400, detail="at least one RBAC role is required")
    return normalized


def _rbac_change_payload_digest(subject_id: str, payload: RoleBindingUpdate) -> str:
    return _control_plane_payload_digest(
        {
            "subjectId": subject_id,
            "roles": _normalized_rbac_roles(payload.roles),
            "reason": payload.reason,
        }
    )


def _rbac_deprovision_payload_digest(payload: DeprovisionSubjectRequest) -> str:
    return _control_plane_payload_digest(
        {
            "subjectId": payload.subject_id,
            "reason": payload.reason,
        }
    )


def _admin_token_rotation_payload_digest(payload: AdminTokenRotateRequest) -> str:
    return _control_plane_payload_digest({"token": "admin", "reason": payload.reason})


def _break_glass_payload_digest(payload: BreakGlassGrantRequest) -> str:
    return _control_plane_payload_digest(
        {
            "principalId": payload.principal_id,
            "routeId": payload.route_id,
            "credentialId": payload.credential_id,
            "credentialVersion": payload.credential_version,
            "policyHash": payload.policy_hash,
            "requestDigest": payload.request_digest,
            "operationDigest": payload.operation_digest,
            "method": payload.method,
            "url": payload.url,
            "grantTtlSeconds": payload.grant_ttl_seconds,
            "grantMaxUses": payload.grant_max_uses,
            "reason": payload.reason,
            "canonicalRequest": payload.canonical_request,
            "redactedDisplay": payload.redacted_display,
        }
    )


def _approval_is_expired(approval: dict[str, Any]) -> bool:
    return datetime.fromisoformat(approval["expires_at"]) <= datetime.now(timezone.utc)


def _approval_body_hash(canonical: dict[str, Any] | None) -> str | None:
    if not isinstance(canonical, dict):
        return None
    request = canonical.get("request") if isinstance(canonical.get("request"), dict) else {}
    for key in ("body_sha256", "bodySha256", "body_hash", "bodyHash"):
        value = request.get(key) or canonical.get(key)
        if value:
            return str(value)
    return None


SENSITIVE_REVIEW_KEY_PARTS = ("authorization", "password", "secret", "token")


def _redact_review_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in SENSITIVE_REVIEW_KEY_PARTS):
                redacted[str(key)] = "[redacted]"
            else:
                redacted[str(key)] = _redact_review_value(item)
        return redacted
    if isinstance(value, list):
        return [_redact_review_value(item) for item in value]
    return value


def _approval_source_identity(canonical: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(canonical, dict):
        return {}
    result: dict[str, Any] = {}
    for key in ("client_ip", "clientIp", "client_cert_sha256", "clientCertSha256", "spiffe_id", "spiffeId"):
        if canonical.get(key):
            result[key] = canonical[key]
    principal = canonical.get("principal") or canonical.get("principal_id")
    if principal:
        result["principal"] = principal
    if canonical.get("proxy_authorization_hash") or canonical.get("proxyAuthorizationHash"):
        result["proxy_authorization"] = "hash-bound"
    return result


def _approval_operation_fields(canonical: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(canonical, dict):
        return {}
    operation = canonical.get("operation")
    if isinstance(operation, dict):
        return _redact_review_value(operation)
    selected: dict[str, Any] = {}
    for key in (
        "operation",
        "operation_type",
        "operationType",
        "package_name",
        "packageName",
        "package_version",
        "packageVersion",
        "tarball_integrity",
        "tarballIntegrity",
        "gmail_user",
        "gmailUser",
    ):
        if canonical.get(key) is not None:
            selected[key] = canonical[key]
    return _redact_review_value(selected)


def _approval_retry_semantics(approval: dict[str, Any], jit: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_action": "retry-identical-request-through-proxy",
        "server_side_grant": True,
        "agent_receives_secret_or_token": False,
        "request_digest": approval.get("request_digest"),
        "operation_digest": approval.get("operation_digest"),
        "consume_on": jit.get("consumeOn") or "forwardStart",
        "grant_ttl_seconds": approval.get("grant_ttl_seconds") or jit.get("ttlSeconds"),
        "grant_max_uses": approval.get("grant_max_uses") or jit.get("maxUses") or 1,
        "retry_after_seconds": 3,
    }


def _approval_risk_flags(approval: dict[str, Any], jit: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    if _approval_is_expired(approval):
        flags.append("approval_expired")
    if approval.get("credential_version") is not None:
        flags.append("credential_version_bound")
    if approval.get("policy_hash"):
        snapshot = get_policy_snapshot()
        flags.append("policy_hash_current" if snapshot and snapshot.hash == approval.get("policy_hash") else "policy_hash_not_current")
    authn = _approval_authn_policy(jit)
    if _webauthn_required(authn):
        flags.append("webauthn_required")
    if authn.get("requireHardwareAttestation"):
        flags.append("hardware_attestation_required")
    if int(approval.get("grant_max_uses") or jit.get("maxUses") or 1) == 1:
        flags.append("one_use_grant")
    return flags


def _approval_history_item(item: dict[str, Any]) -> dict[str, Any]:
    authn = item.get("approval_authn") if isinstance(item.get("approval_authn"), dict) else {}
    return {
        "id": item["id"],
        "status": item.get("status"),
        "requested_at": item.get("requested_at"),
        "expires_at": item.get("expires_at"),
        "approved_until": item.get("approved_until"),
        "decision_note": item.get("decision_note"),
        "approved_by": item.get("approved_by"),
        "authn": {
            "method": authn.get("method"),
            "authenticator_class": authn.get("authenticator_class"),
            "user_verified": authn.get("user_verified"),
        },
        "request_digest": item.get("request_digest"),
        "operation_digest": item.get("operation_digest"),
    }


def _approval_review_document(approval: dict[str, Any]) -> dict[str, Any]:
    canonical = approval.get("canonical_request") if isinstance(approval.get("canonical_request"), dict) else {}
    redacted_display = approval.get("redacted_display") if isinstance(approval.get("redacted_display"), dict) else {}
    try:
        jit = _approval_jit_policy(approval)
    except HTTPException:
        jit = {}
    similar = db.list_similar_approvals(approval, limit=5)
    return {
        "id": approval["id"],
        "status": approval.get("status"),
        "principal_id": approval.get("principal_id"),
        "source_identity": _approval_source_identity(canonical),
        "route_id": approval.get("route_id"),
        "credential_ref": approval.get("credential_id"),
        "credential_version": approval.get("credential_version"),
        "policy_hash": approval.get("policy_hash"),
        "method": approval.get("method"),
        "url": approval.get("url"),
        "normalized_operation_fields": _approval_operation_fields(canonical),
        "body_hash": _approval_body_hash(canonical),
        "redacted_payload_summary": _redact_review_value(redacted_display),
        "risk_flags": _approval_risk_flags(approval, jit),
        "requested_at": approval.get("requested_at"),
        "expires_at": approval.get("expires_at"),
        "previous_similar_approvals": [_approval_history_item(item) for item in similar],
        "retry_semantics": _approval_retry_semantics(approval, jit),
    }


@app.get("/attestation")
def attestation(nonce: str | None = None) -> dict[str, Any]:
    return attestation_document(nonce)


@app.post("/api/ca/install-sessions")
def ca_install_session_create(identity: AdminIdentity = Depends(require_role("admin"))) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(18)
    session = {
        "id": session_id,
        "nonce": secrets.token_urlsafe(24),
        "status": "active",
        "token_sha256": _sha256_text(token),
        "created_at": now.isoformat(),
        "created_by": identity.user_id,
        "expires_at": (now + timedelta(seconds=CA_INSTALL_SESSION_TTL_SECONDS)).isoformat(),
        "consumed_at": None,
        "consumed_by": None,
    }
    state = _read_ca_install_sessions()
    state.setdefault("sessions", {})[session_id] = session
    _write_ca_install_sessions(state)
    db.record_audit_event(
        "ca.install_session.created",
        {
            "session_id": session_id,
            "nonce": session["nonce"],
            "expires_at": session["expires_at"],
            "install_method": "verifier-mediated-attestation",
            "token_sha256": session["token_sha256"],
        },
        actor_id=identity.user_id,
    )
    return {"ok": True, "session": _ca_install_session_public(session, include_token=token)}


@app.get("/api/ca/install-sessions/{session_id}/ca.pem")
def ca_install_session_download(
    session_id: str,
    x_serverware_ca_install_token: str | None = Header(default=None, alias="X-Serverware-CA-Install-Token"),
    identity: AdminIdentity = Depends(require_role("admin")),
) -> FileResponse:
    if not x_serverware_ca_install_token:
        raise HTTPException(status_code=401, detail="CA install token required")
    state = _read_ca_install_sessions()
    sessions = state.setdefault("sessions", {})
    session = sessions.get(session_id)
    if not isinstance(session, dict):
        raise HTTPException(status_code=404, detail="CA install session not found")
    if session.get("status") != "active":
        raise HTTPException(status_code=409, detail=f"CA install session is {session.get('status')}")
    expires_at = _parse_iso_datetime(session.get("expires_at"))
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        session["status"] = "expired"
        _write_ca_install_sessions(state)
        raise HTTPException(status_code=410, detail="CA install session expired")
    if not hmac.compare_digest(str(session.get("token_sha256") or ""), _sha256_text(x_serverware_ca_install_token)):
        raise HTTPException(status_code=403, detail="CA install token mismatch")
    if not _ca_cert_path().exists():
        raise HTTPException(status_code=404, detail="mitmproxy CA has not been generated yet")
    session["status"] = "consumed"
    session["consumed_at"] = _now_iso()
    session["consumed_by"] = identity.user_id
    _write_ca_install_sessions(state)
    db.record_audit_event(
        "ca.install_session.consumed",
        {
            "session_id": session_id,
            "nonce": session.get("nonce"),
            "install_method": "verifier-mediated-attestation",
            "token_sha256": session.get("token_sha256"),
        },
        actor_id=identity.user_id,
    )
    return _ca_file_response(headers={"X-Serverware-CA-Install-Session": session_id})


@app.get("/api/release/provenance")
def release_provenance_api(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    document = release_provenance_document()
    if document is None:
        raise HTTPException(status_code=404, detail="release provenance has not been published")
    return document


@app.get("/api/release/image-signatures")
def image_signatures_api(_: AdminIdentity = Depends(require_role("auditor"))) -> dict[str, Any]:
    document = image_signatures_document()
    if document is None:
        raise HTTPException(status_code=404, detail="image signatures have not been published")
    return document


@app.get("/ca.pem")
def ca_pem(identity: AdminIdentity = Depends(require_role("admin"))) -> FileResponse:
    if not DIRECT_CA_DOWNLOAD_ENABLED:
        raise HTTPException(status_code=403, detail="direct CA download is disabled; use verifier-mediated install sessions")
    db.record_audit_event(
        "ca.direct_download",
        {
            "debug_only": True,
            "install_method": "direct-debug-download",
        },
        actor_id=identity.user_id,
    )
    return _ca_file_response(
        headers={
            "X-Serverware-Debug-Only": "true",
            "X-Serverware-Install-Path": "debug-direct-download",
        }
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
def bootstrap(identity: AdminIdentity = Depends(require_admin)) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else {}
    credentials = db.list_credentials()
    routes = db.list_routes()
    approvals = db.list_approvals(limit=100)
    logs = db.list_logs(limit=150)
    result = {
        "credentials": credentials,
        "routes": routes,
        "approvals": approvals,
        "logs": logs,
        "ca_ready": (MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem").exists(),
        "policy_ready": snapshot is not None,
        "policy_hash": snapshot.hash if snapshot else None,
        "policy_signature": metadata.get("signature") if isinstance(metadata, dict) else None,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "policy_path": str(POLICY_BUNDLE_PATH),
        "oauthProviders": provider_status(),
        **admin_status(),
    }
    db.record_audit_event(
        "control_plane.bootstrap",
        {
            "policy_hash": snapshot.hash if snapshot else None,
            "counts": {
                "credentials": len(credentials),
                "routes": len(routes),
                "approvals": len(approvals),
                "logs": len(logs),
            },
            "auth_method": identity.auth_method,
        },
        actor_id=identity.user_id,
    )
    return result


@app.get("/api/csrf")
def csrf_token(response: Response, request: Request, _: AdminIdentity = Depends(require_admin)) -> dict[str, Any]:
    token = issue_csrf_cookie(response, request)
    return {
        "ok": True,
        "token": token,
        "cookie": CSRF_COOKIE_NAME,
        "header": CSRF_HEADER_NAME,
    }


@app.post("/api/control-plane/mutations/webauthn/options")
def control_plane_mutation_webauthn_options(
    payload: ControlPlaneMutationWebAuthnOptions,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author", "policy_publisher", "credential_owner", "approver")),
) -> dict[str, Any]:
    return control_plane_mutation_options(
        user_id=identity.user_id,
        action=payload.action,
        resource_id=payload.resource_id,
        payload_digest=payload.payload_digest,
        authn_policy=_control_plane_mutation_authn_policy(),
    )


@app.get("/api/rbac/role-bindings")
def rbac_role_bindings(_: AdminIdentity = Depends(require_role("admin", "auditor"))) -> dict[str, Any]:
    return _read_rbac_bindings()


@app.put("/api/rbac/role-bindings/{subject_id:path}")
def rbac_role_binding_update(
    subject_id: str,
    payload: RoleBindingUpdate,
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    roles = _normalized_rbac_roles(payload.roles)
    payload_digest = _rbac_change_payload_digest(subject_id, payload)
    mfa = _require_control_plane_mutation_mfa(
        action="rbac.role.change",
        resource_id=subject_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="rbac.role.change",
        resource_id=subject_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={"subject_id": subject_id, "roles": roles, "reason": payload.reason},
    )
    state = _read_rbac_bindings()
    subjects = state.setdefault("subjects", {})
    previous = subjects.get(subject_id) if isinstance(subjects.get(subject_id), dict) else {}
    previous_roles = previous.get("roles") or []
    binding = {
        "subject_id": subject_id,
        "roles": roles,
        "status": "active",
        "updated_at": _now_iso(),
        "updated_by": identity.user_id,
        "reason": payload.reason,
    }
    subjects[subject_id] = binding
    _write_rbac_bindings(state)
    db.record_audit_event(
        "rbac.role_changed",
        {
            "subject_id": subject_id,
            "previous_roles": previous_roles,
            "new_roles": roles,
            "reason": payload.reason,
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return {"ok": True, "binding": binding}


@app.post("/api/rbac/deprovision")
def rbac_deprovision_subject(
    payload: DeprovisionSubjectRequest,
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    payload_digest = _rbac_deprovision_payload_digest(payload)
    mfa = _require_control_plane_mutation_mfa(
        action="rbac.deprovision",
        resource_id=payload.subject_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="rbac.deprovision",
        resource_id=payload.subject_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={"subject_id": payload.subject_id, "reason": payload.reason},
    )
    state = _read_rbac_bindings()
    subjects = state.setdefault("subjects", {})
    previous = subjects.get(payload.subject_id) if isinstance(subjects.get(payload.subject_id), dict) else {}
    previous_roles = previous.get("roles") or []
    binding = {
        "subject_id": payload.subject_id,
        "roles": [],
        "status": "deprovisioned",
        "deprovisioned_at": _now_iso(),
        "deprovisioned_by": identity.user_id,
        "reason": payload.reason,
    }
    subjects[payload.subject_id] = binding
    _write_rbac_bindings(state)
    db.record_audit_event(
        "rbac.deprovisioned",
        {
            "subject_id": payload.subject_id,
            "previous_roles": previous_roles,
            "reason": payload.reason,
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return {"ok": True, "binding": binding}


@app.post("/api/control-plane/tokens/admin/rotate")
def control_plane_admin_token_rotate(
    payload: AdminTokenRotateRequest | None = Body(default=None),
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    request_payload = payload if isinstance(payload, AdminTokenRotateRequest) else AdminTokenRotateRequest()
    payload_digest = _admin_token_rotation_payload_digest(request_payload)
    mfa = _require_control_plane_mutation_mfa(
        action="control_plane.token.rotate",
        resource_id="admin-token",
        payload_digest=payload_digest,
        mfa=request_payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="control_plane.token.rotate",
        resource_id="admin-token",
        payload_digest=payload_digest,
        mfa=request_payload.mfa,
        identity=identity,
        request={"token": "admin", "reason": request_payload.reason},
    )
    try:
        rotated = rotate_generated_admin_token()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.record_audit_event(
        "control_plane.token_rotated",
        {
            "token": "admin",
            "token_path": rotated["token_path"],
            "previous_token_sha256": rotated["previous_token_sha256"],
            "new_token_sha256": rotated["token_sha256"],
            "reason": request_payload.reason,
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return {
        "ok": True,
        "token": rotated["token"],
        "tokenSha256": rotated["token_sha256"],
        "tokenPath": rotated["token_path"],
    }


@app.get("/api/control-plane/approvals")
def control_plane_approvals(
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    _: AdminIdentity = Depends(require_role("auditor", "policy_publisher", "credential_owner", "policy_author")),
) -> list[dict[str, Any]]:
    return db.list_control_plane_approvals(status=status, limit=limit)


@app.post("/api/control-plane/approvals/{approval_id}/approve")
def control_plane_approval_approve(
    approval_id: str,
    payload: ControlPlaneApprovalDecision | None = Body(default=None),
    identity: AdminIdentity = Depends(require_admin),
) -> dict[str, Any]:
    decision = payload if isinstance(payload, ControlPlaneApprovalDecision) else None
    approval = db.get_control_plane_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="control-plane approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"control-plane approval is already {approval['status']}")
    if approval["requester_id"] == identity.user_id:
        raise HTTPException(status_code=403, detail="requester cannot approve their own control-plane mutation")
    _assert_control_plane_approval_role(identity, approval["action"])
    updated = db.approve_control_plane_approval(
        approval_id,
        actor_id=identity.user_id,
        note=decision.note if decision else None,
        authn={"method": identity.auth_method, "user_id": identity.user_id},
    )
    if not updated:
        raise HTTPException(status_code=409, detail="control-plane approval state changed before it could be approved")
    return updated


@app.post("/api/control-plane/approvals/{approval_id}/deny")
def control_plane_approval_deny(
    approval_id: str,
    payload: ControlPlaneApprovalDecision | None = Body(default=None),
    identity: AdminIdentity = Depends(require_admin),
) -> dict[str, Any]:
    decision = payload if isinstance(payload, ControlPlaneApprovalDecision) else None
    approval = db.get_control_plane_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="control-plane approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"control-plane approval is already {approval['status']}")
    _assert_control_plane_approval_role(identity, approval["action"])
    updated = db.deny_control_plane_approval(
        approval_id,
        actor_id=identity.user_id,
        note=decision.note if decision else None,
    )
    if not updated:
        raise HTTPException(status_code=409, detail="control-plane approval state changed before it could be denied")
    return updated


@app.post("/api/policy/candidate")
def policy_candidate(
    payload: PolicyCandidateRequest,
    _: AdminIdentity = Depends(require_role("policy_author", "policy_publisher")),
) -> dict[str, Any]:
    return _policy_candidate_report(bundle=payload.bundle, dry_run=payload.dry_run, enforce_monotonic=False)


@app.post("/api/policy/publish")
def policy_publish(
    payload: PolicyPublishRequest,
    identity: AdminIdentity = Depends(require_role("policy_publisher")),
) -> dict[str, Any]:
    report = _policy_candidate_report(bundle=payload.bundle, dry_run=payload.dry_run, enforce_monotonic=True)
    metadata = report["signedBundle"].get("metadata") if isinstance(report["signedBundle"].get("metadata"), dict) else {}
    policy_id = metadata.get("id")
    payload_digest = _policy_publish_payload_digest(payload)
    if payload.activation_mode == "full" and POLICY_CANARY_REQUIRED:
        raise HTTPException(status_code=412, detail="policy canary activation is required before full publish")
    mfa = _require_control_plane_mutation_mfa(
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "policy_id": policy_id,
            "previous_policy_hash": report["current"]["policyHash"],
            "candidate_policy_hash": report["candidate"]["policyHash"],
            "previous_sequence": report["current"]["sequence"],
            "new_sequence": metadata.get("sequence"),
            "previous_rollback_epoch": report["current"]["rollbackEpoch"],
            "new_rollback_epoch": metadata.get("rollbackEpoch"),
            "diff": report["diff"],
            "dry_run": report["dryRun"],
        },
    )
    if payload.activation_mode == "canary":
        return _start_policy_canary(
            report=report,
            payload=payload,
            payload_digest=payload_digest,
            identity=identity,
            mfa=mfa,
            two_person=two_person,
        )
    snapshot = write_policy_bundle(payload.bundle)
    db.record_audit_event(
        "policy.published",
        {
            "activation_mode": "full",
            "policy_id": policy_id,
            "previous_policy_hash": report["current"]["policyHash"],
            "new_policy_hash": snapshot.hash,
            "previous_sequence": report["current"]["sequence"],
            "new_sequence": metadata.get("sequence"),
            "previous_rollback_epoch": report["current"]["rollbackEpoch"],
            "new_rollback_epoch": metadata.get("rollbackEpoch"),
            "diff": report["diff"],
            "dry_run": report["dryRun"],
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    report = dict(report)
    report["published"] = True
    report["policyHash"] = snapshot.hash
    report.pop("signedBundle", None)
    return report


@app.get("/api/policy/canary/status")
def policy_canary_status(
    _: AdminIdentity = Depends(require_role("auditor", "policy_publisher", "policy_author")),
) -> dict[str, Any]:
    state = _read_policy_canary_state()
    if not state:
        raise HTTPException(status_code=404, detail="policy canary is not running")
    return {
        "ok": True,
        "canary": _policy_canary_public(state),
        "monitoring": _policy_canary_monitor(state),
    }


@app.post("/api/policy/canary/activate")
def policy_canary_activate(
    payload: PolicyCanaryActivationRequest,
    identity: AdminIdentity = Depends(require_role("policy_publisher")),
) -> dict[str, Any]:
    state = _read_policy_canary_state()
    if not state or state.get("id") != payload.canary_id:
        raise HTTPException(status_code=404, detail="policy canary not found")
    if state.get("status") != "running":
        raise HTTPException(status_code=409, detail=f"policy canary is {state.get('status')}")
    signed_bundle = state.get("signed_bundle")
    if not isinstance(signed_bundle, dict):
        raise HTTPException(status_code=503, detail="policy canary signed bundle is missing")
    try:
        candidate = compile_policy_bundle(signed_bundle, verify_signature=True, validate_schema=True)
    except PolicyBundleError as exc:
        raise HTTPException(status_code=409, detail=f"policy canary bundle is invalid: {exc}") from exc
    if candidate.hash != state.get("candidate_policy_hash"):
        raise HTTPException(status_code=409, detail="policy canary bundle hash no longer matches state")
    current = get_policy_snapshot()
    current_hash = current.hash if current else None
    if current_hash != state.get("previous_policy_hash"):
        raise HTTPException(status_code=409, detail="active policy changed after canary start")
    _assert_policy_publish_monotonic(current.raw if current else None, signed_bundle)
    monitor = _policy_canary_monitor(state)
    thresholds = _require_policy_canary_activation_thresholds(state, monitor, payload)
    payload_digest = _policy_canary_activate_payload_digest(payload)
    metadata = signed_bundle.get("metadata") if isinstance(signed_bundle.get("metadata"), dict) else {}
    policy_id = metadata.get("id")
    mfa = _require_control_plane_mutation_mfa(
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "canary_id": state.get("id"),
            "policy_id": policy_id,
            "previous_policy_hash": state.get("previous_policy_hash"),
            "candidate_policy_hash": state.get("candidate_policy_hash"),
            "candidate_sequence": state.get("candidate_sequence"),
            "candidate_rollback_epoch": state.get("candidate_rollback_epoch"),
            "monitoring": monitor,
            "thresholds": thresholds,
        },
    )
    snapshot = write_policy_bundle(signed_bundle)
    activated_at = _now_iso()
    state.update(
        {
            "status": "activated",
            "activated_at": activated_at,
            "activated_by": identity.user_id,
            "activation_payload_digest": payload_digest,
            "activation_monitoring": monitor,
            "activation_thresholds": thresholds,
            "activation_control_plane_mfa": mfa,
            "activation_control_plane_approval": two_person,
        }
    )
    _write_policy_canary_state(state)
    audit_payload = {
        "activation_mode": "canary",
        "canary_id": state.get("id"),
        "policy_id": policy_id,
        "previous_policy_hash": state.get("previous_policy_hash"),
        "new_policy_hash": snapshot.hash,
        "previous_sequence": (current.raw.get("metadata") or {}).get("sequence") if current else None,
        "new_sequence": metadata.get("sequence"),
        "previous_rollback_epoch": (current.raw.get("metadata") or {}).get("rollbackEpoch") if current else None,
        "new_rollback_epoch": metadata.get("rollbackEpoch"),
        "diff": state.get("diff"),
        "dry_run": state.get("dry_run"),
        "canary_monitoring": monitor,
        "canary_thresholds": thresholds,
        "control_plane_mfa": mfa,
        "control_plane_approval": two_person,
        "payload_digest": payload_digest,
    }
    db.record_audit_event("policy.canary.activated", audit_payload, actor_id=identity.user_id)
    db.record_audit_event("policy.published", audit_payload, actor_id=identity.user_id)
    return {
        "ok": True,
        "published": True,
        "policyHash": snapshot.hash,
        "candidate": {
            "policyHash": candidate.hash,
            "signingKeyId": metadata.get("signingKeyId"),
            "signature": metadata.get("signature"),
            "sequence": metadata.get("sequence"),
            "rollbackEpoch": metadata.get("rollbackEpoch"),
            "routes": len(candidate.routes),
            "principals": len(candidate.principals),
            "credentials": len(candidate.credentials),
        },
        "canary": _policy_canary_public(state),
        "monitoring": monitor,
        "thresholds": thresholds,
        "diff": state.get("diff"),
        "dryRun": state.get("dry_run"),
    }


@app.post("/api/policy/canary/cancel")
def policy_canary_cancel(
    payload: PolicyCanaryCancelRequest,
    identity: AdminIdentity = Depends(require_role("policy_publisher")),
) -> dict[str, Any]:
    state = _read_policy_canary_state()
    if not state or state.get("id") != payload.canary_id:
        raise HTTPException(status_code=404, detail="policy canary not found")
    if state.get("status") != "running":
        raise HTTPException(status_code=409, detail=f"policy canary is {state.get('status')}")
    state.update(
        {
            "status": "cancelled",
            "cancelled_at": _now_iso(),
            "cancelled_by": identity.user_id,
            "cancel_note": payload.note,
        }
    )
    _write_policy_canary_state(state)
    db.record_audit_event(
        "policy.canary.cancelled",
        {
            "canary_id": state.get("id"),
            "policy_id": state.get("policy_id"),
            "candidate_policy_hash": state.get("candidate_policy_hash"),
            "note": payload.note,
        },
        actor_id=identity.user_id,
    )
    return {"ok": True, "canary": _policy_canary_public(state)}


@app.post("/api/agents/enrollment")
def agent_enrollment(
    payload: AgentEnrollmentCreate,
    _: AdminIdentity = Depends(require_role("policy_author")),
) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if snapshot is None:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    try:
        return build_agent_enrollment(
            snapshot=snapshot,
            principal_id=payload.principal_id,
            attestation=attestation_document(None),
            proxy_url=payload.proxy_url,
            control_plane_url=payload.control_plane_url,
            proxy_egress_cidrs=payload.proxy_egress_cidrs,
            namespace=payload.namespace,
            pod_selector=payload.pod_selector,
            ca_mount_path=payload.ca_mount_path,
        )
    except AgentEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/oauth/providers")
def oauth_providers(_: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner"))) -> dict[str, Any]:
    return {"providers": provider_status()}


@app.post("/api/oauth/start")
def oauth_start(
    payload: OAuthStartRequest,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner")),
) -> dict[str, Any]:
    mutation_payload = payload.model_dump(exclude={"mfa"})
    payload_digest = _control_plane_payload_digest(mutation_payload)
    mfa = _require_control_plane_mutation_mfa(
        action="credential.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="credential.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "credential_type": "oauth2",
            "provider": payload.provider,
            "credential_name": payload.credential_name,
            "scopes": payload.scopes or [],
            "metadata_keys": sorted(payload.metadata),
        },
    )
    try:
        started = create_authorization_url(
            provider_id=payload.provider,
            credential_name=payload.credential_name,
            scopes=payload.scopes,
            metadata=payload.metadata,
            actor_id=identity.user_id,
            control_plane_mfa=mfa,
            control_plane_approval=two_person,
        )
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.record_audit_event(
        "credential.oauth_authorization_started",
        {
            "provider": started["provider"],
            "credential_name": payload.credential_name,
            "scopes": started["scopes"],
            "state_hash": "sha256:" + hashlib.sha256(started["state"].encode("ascii")).hexdigest(),
            "expires_at_epoch": started["expiresAtEpoch"],
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return started


@app.get("/api/oauth/callback/{provider_id}")
def oauth_callback(
    provider_id: str,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> HTMLResponse:
    if error:
        detail = html.escape(error_description or error)
        return HTMLResponse(
            f"<h1>OAuth denied</h1><p>{detail}</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
    if not code or not state:
        return HTMLResponse(
            "<h1>OAuth failed</h1><p>Missing code or state.</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
    try:
        exchanged = exchange_authorization_code(provider_id=provider_id, code=code, state=state)
    except OAuthError as exc:
        detail = html.escape(str(exc))
        return HTMLResponse(
            f"<h1>OAuth failed</h1><p>{detail}</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
    credential = db.create_credential(
        exchanged["name"],
        exchanged["kind"],
        exchanged["secret"],
        exchanged["metadata"],
    )
    runtime.publish_credential_generation(credential["id"], int(credential["credential_version"]))
    runtime.publish_credential_lease_from_db(credential["id"])
    actor_id = exchanged.get("createdBy") or "oauth-callback"
    db.record_audit_event(
        "credential.oauth_connected",
        {
            "credential_id": credential["id"],
            "name": credential["name"],
            "kind": credential["kind"],
            "credential_version": credential.get("credential_version"),
            "secret_kek_id": credential.get("secret_kek_id"),
            "provider": exchanged["provider"],
            "scopes": exchanged["scopes"],
            "expires_at_epoch_ms": exchanged.get("expiresAtEpochMs"),
            "control_plane_mfa": exchanged.get("controlPlaneMfa"),
            "control_plane_approval": exchanged.get("controlPlaneApproval"),
        },
        actor_id=actor_id,
    )
    return HTMLResponse(
        """
        <h1>OAuth credential connected</h1>
        <p>The credential is encrypted in Serverware and can now be assigned to a policy route.</p>
        <script>
          setTimeout(() => { window.location.href = "/"; }, 1200);
        </script>
        """,
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/credentials")
def create_credential(payload: CredentialCreate, identity: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner"))) -> dict[str, Any]:
    mutation_payload = payload.model_dump(exclude={"mfa"})
    payload_digest = _control_plane_payload_digest(mutation_payload)
    mfa = _require_control_plane_mutation_mfa(
        action="credential.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="credential.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "name": payload.name,
            "kind": payload.kind,
            "metadata_keys": sorted(payload.metadata),
        },
    )
    created = db.create_credential(payload.name, payload.kind, payload.secret, payload.metadata)
    db.record_audit_event(
        "credential.created",
        {
            "credential_id": created["id"],
            "name": created["name"],
            "kind": created["kind"],
            "credential_version": created.get("credential_version"),
            "secret_kek_id": created.get("secret_kek_id"),
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    runtime.publish_credential_generation(created["id"], int(created["credential_version"]))
    runtime.publish_credential_lease_from_db(created["id"])
    return created


@app.put("/api/credentials/{credential_id}")
def update_credential(
    credential_id: str,
    payload: CredentialUpdate,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner")),
) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True, exclude={"mfa"})
    payload_digest = _control_plane_payload_digest({"credential_id": credential_id, "changes": changes})
    mfa = _require_control_plane_mutation_mfa(
        action="credential.update",
        resource_id=credential_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="credential.update",
        resource_id=credential_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "credential_id": credential_id,
            "changed_fields": sorted(changes),
            "secret_changed": "secret" in changes,
        },
    )
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
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    runtime.publish_credential_generation(credential_id, int(updated["credential_version"]))
    runtime.publish_credential_lease_from_db(credential_id)
    return updated


@app.delete("/api/credentials/{credential_id}")
def delete_credential(
    credential_id: str,
    payload: ControlPlaneMutationMfa | None = Body(default=None),
    identity: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner")),
) -> dict[str, Any]:
    payload_digest = _control_plane_payload_digest({"credential_id": credential_id})
    mfa = _require_control_plane_mutation_mfa(
        action="credential.delete",
        resource_id=credential_id,
        payload_digest=payload_digest,
        mfa=payload.mfa if payload else None,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="credential.delete",
        resource_id=credential_id,
        payload_digest=payload_digest,
        mfa=payload.mfa if payload else None,
        identity=identity,
        request={"credential_id": credential_id},
    )
    deleted = db.delete_credential(credential_id)
    if deleted:
        db.record_audit_event(
            "credential.deleted",
            {
                "credential_id": credential_id,
                "control_plane_mfa": mfa,
                "control_plane_approval": two_person,
                "payload_digest": payload_digest,
            },
            actor_id=identity.user_id,
        )
        runtime.publish_credential_generation(credential_id, deleted=True)
        runtime.publish_credential_lease(credential_id, deleted=True)
    return {"deleted": deleted}


@app.post("/api/routes")
def create_route(payload: RouteCreate, identity: AdminIdentity = Depends(require_role("admin", "policy_author"))) -> dict[str, Any]:
    data = payload.model_dump(exclude={"mfa"})
    if data.get("credential_id") == "":
        data["credential_id"] = None
    payload_digest = _control_plane_payload_digest(data)
    mfa = _require_control_plane_mutation_mfa(
        action="route.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="route.create",
        resource_id=None,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "name": data.get("name"),
            "match_host": data.get("match_host"),
            "match_path_prefix": data.get("match_path_prefix"),
            "credential_id": data.get("credential_id"),
            "enabled": data.get("enabled"),
        },
    )
    created = db.create_route(data)
    db.record_audit_event(
        "route.created",
        {
            "route_id": created["id"],
            "name": created["name"],
            "match_host": created["match_host"],
            "match_path_prefix": created["match_path_prefix"],
            "credential_id": created["credential_id"],
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return created


@app.put("/api/routes/{route_id}")
def update_route(
    route_id: str,
    payload: RouteUpdate,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author")),
) -> dict[str, Any]:
    data = payload.model_dump(exclude_unset=True, exclude={"mfa"})
    if data.get("credential_id") == "":
        data["credential_id"] = None
    payload_digest = _control_plane_payload_digest({"route_id": route_id, "changes": data})
    mfa = _require_control_plane_mutation_mfa(
        action="route.update",
        resource_id=route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="route.update",
        resource_id=route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "route_id": route_id,
            "changed_fields": sorted(data),
            "match_host": data.get("match_host"),
            "match_path_prefix": data.get("match_path_prefix"),
            "credential_id": data.get("credential_id"),
            "enabled": data.get("enabled"),
        },
    )
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
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return updated


@app.delete("/api/routes/{route_id}")
def delete_route(
    route_id: str,
    payload: ControlPlaneMutationMfa | None = Body(default=None),
    identity: AdminIdentity = Depends(require_role("admin", "policy_author")),
) -> dict[str, Any]:
    payload_digest = _control_plane_payload_digest({"route_id": route_id})
    mfa = _require_control_plane_mutation_mfa(
        action="route.delete",
        resource_id=route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa if payload else None,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="route.delete",
        resource_id=route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa if payload else None,
        identity=identity,
        request={"route_id": route_id},
    )
    deleted = db.delete_route(route_id)
    if deleted:
        db.record_audit_event(
            "route.deleted",
            {
                "route_id": route_id,
                "control_plane_mfa": mfa,
                "control_plane_approval": two_person,
                "payload_digest": payload_digest,
            },
            actor_id=identity.user_id,
        )
    return {"deleted": deleted}


@app.post("/api/break-glass/grants")
@app.post("/v1/break-glass/grants")
def break_glass_grant(
    payload: BreakGlassGrantRequest,
    identity: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    payload_digest = _break_glass_payload_digest(payload)
    mfa = _require_control_plane_mutation_mfa(
        action="break_glass.grant",
        resource_id=payload.route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    two_person = _require_control_plane_two_person(
        action="break_glass.grant",
        resource_id=payload.route_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
        request={
            "principal_id": payload.principal_id,
            "route_id": payload.route_id,
            "credential_id": payload.credential_id,
            "credential_version": payload.credential_version,
            "policy_hash": payload.policy_hash,
            "request_digest": payload.request_digest,
            "operation_digest": payload.operation_digest,
            "grant_ttl_seconds": payload.grant_ttl_seconds,
            "grant_max_uses": payload.grant_max_uses,
            "reason": payload.reason,
        },
    )
    approval = db.ensure_jit_approval_request(
        route_id=payload.route_id,
        method=payload.method,
        url=payload.url,
        principal_id=payload.principal_id,
        credential_id=payload.credential_id,
        credential_version=payload.credential_version,
        policy_hash=payload.policy_hash,
        request_digest=payload.request_digest,
        operation_digest=payload.operation_digest,
        canonical_request={
            **payload.canonical_request,
            "break_glass": True,
            "reason": payload.reason,
        },
        redacted_display={
            **payload.redacted_display,
            "break_glass": True,
            "reason": payload.reason,
        },
        pending_ttl_seconds=60,
        grant_ttl_seconds=payload.grant_ttl_seconds,
        grant_max_uses=payload.grant_max_uses,
    )
    approved = db.approve_request(
        approval["id"],
        ttl_seconds=payload.grant_ttl_seconds,
        note=f"break-glass: {payload.reason}",
        actor_id=identity.user_id,
        authn={
            "method": "break_glass",
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
    )
    if not approved:
        raise HTTPException(status_code=409, detail="break-glass grant could not be approved")
    db.record_audit_event(
        "approval.break_glass_granted",
        {
            "approval_request_id": approved["id"],
            "principal_id": payload.principal_id,
            "route_id": payload.route_id,
            "credential_id": payload.credential_id,
            "credential_version": payload.credential_version,
            "policy_hash": payload.policy_hash,
            "request_digest": payload.request_digest,
            "operation_digest": payload.operation_digest,
            "grant_ttl_seconds": payload.grant_ttl_seconds,
            "grant_max_uses": payload.grant_max_uses,
            "reason": payload.reason,
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    return {
        "ok": True,
        "approvalId": approved["id"],
        "grantRef": f"approval:{approved['id']}",
        "principalId": payload.principal_id,
        "routeId": payload.route_id,
        "credentialId": payload.credential_id,
        "credentialVersion": payload.credential_version,
        "policyHash": payload.policy_hash,
        "requestDigest": payload.request_digest,
        "operationDigest": payload.operation_digest,
        "expiresAt": approved.get("approved_until"),
        "grantMaxUses": payload.grant_max_uses,
    }


@app.get("/api/approvals")
def approvals(status: str | None = None, _: AdminIdentity = Depends(require_role("approver", "auditor"))) -> list[dict[str, Any]]:
    return db.list_approvals(status=status, limit=100)


@app.get("/api/approvals/{approval_id}/review")
def approval_review(
    approval_id: str,
    _: AdminIdentity = Depends(require_role("approver", "auditor")),
) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    return _approval_review_document(approval)


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
def deny(
    approval_id: str,
    payload: ApprovalDeny | None = Body(default=None),
    identity: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    decision = payload if isinstance(payload, ApprovalDeny) else None
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail=f"approval is already {approval['status']}")
    if _approval_is_expired(approval):
        raise HTTPException(status_code=409, detail="approval is expired")
    _assert_approver_allowed(identity, _approval_jit_policy(approval))
    updated = db.deny_request(approval_id, note=decision.reason if decision else None, actor_id=identity.user_id)
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


@app.get("/api/audit/search")
def audit_search(
    limit: int = Query(100, ge=1, le=1000),
    scan_limit: int = Query(5000, ge=1, le=50000, alias="scanLimit"),
    event_type: str | None = Query(default=None, alias="eventType"),
    actor_type: str | None = Query(default=None, alias="actorType"),
    actor_id: str | None = Query(default=None, alias="actorId"),
    principal_id: str | None = Query(default=None, alias="principalId"),
    route_id: str | None = Query(default=None, alias="routeId"),
    policy_hash: str | None = Query(default=None, alias="policyHash"),
    credential_id: str | None = Query(default=None, alias="credentialId"),
    credential_version: int | None = Query(default=None, alias="credentialVersion"),
    approval_id: str | None = Query(default=None, alias="approvalId"),
    decision: str | None = None,
    attestation_measurement: str | None = Query(default=None, alias="attestationMeasurement"),
    start: str | None = None,
    end: str | None = None,
    q: str | None = None,
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    return db.search_audit_events(
        limit=limit,
        scan_limit=scan_limit,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        principal_id=principal_id,
        route_id=route_id,
        policy_hash=policy_hash,
        credential_id=credential_id,
        credential_version=credential_version,
        approval_id=approval_id,
        decision=decision,
        attestation_measurement=attestation_measurement,
        start=start,
        end=end,
        q=q,
    )


@app.get("/api/audit/export")
def audit_export(
    limit: int = Query(1000, ge=1, le=10000),
    scan_limit: int = Query(50000, ge=1, le=50000, alias="scanLimit"),
    event_type: str | None = Query(default=None, alias="eventType"),
    actor_type: str | None = Query(default=None, alias="actorType"),
    actor_id: str | None = Query(default=None, alias="actorId"),
    principal_id: str | None = Query(default=None, alias="principalId"),
    route_id: str | None = Query(default=None, alias="routeId"),
    policy_hash: str | None = Query(default=None, alias="policyHash"),
    credential_id: str | None = Query(default=None, alias="credentialId"),
    credential_version: int | None = Query(default=None, alias="credentialVersion"),
    approval_id: str | None = Query(default=None, alias="approvalId"),
    decision: str | None = None,
    attestation_measurement: str | None = Query(default=None, alias="attestationMeasurement"),
    start: str | None = None,
    end: str | None = None,
    q: str | None = None,
    _: AdminIdentity = Depends(require_role("auditor")),
) -> Response:
    return Response(
        content=db.export_audit_events_jsonl(
            limit=limit,
            scan_limit=scan_limit,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            principal_id=principal_id,
            route_id=route_id,
            policy_hash=policy_hash,
            credential_id=credential_id,
            credential_version=credential_version,
            approval_id=approval_id,
            decision=decision,
            attestation_measurement=attestation_measurement,
            start=start,
            end=end,
            q=q,
        ),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="serverware-audit-export.jsonl"',
        },
    )


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
    if result.get("consumed"):
        return {"ok": True, **result}
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if snapshot.hash != payload.policy_hash:
        raise HTTPException(status_code=409, detail="data-plane policy hash is not active")
    route = _active_route_by_id(payload.route_id)
    if route.credential_ref and route.credential_ref != payload.credential_ref:
        raise HTTPException(status_code=409, detail="data-plane credential reference does not match active route")
    jit = route.jit or {}
    if not jit.get("required"):
        return {"ok": True, **result}
    pending_ttl = max(1, min(int(jit.get("pendingTtlSeconds", 300)), 3600))
    grant_ttl = max(1, min(int(jit.get("ttlSeconds", 30)), 3600))
    max_uses = max(1, int(jit.get("maxUses", 1)))
    redacted_display = payload.redacted_display or {
        "method": payload.method,
        "url": payload.url,
        "route_id": payload.route_id,
        "principal": payload.principal_id,
        "operation": payload.canonical_request.get("operation"),
        "body_sha256": (payload.canonical_request.get("request") or {}).get("body_sha256"),
    }
    approval = db.ensure_jit_approval_request(
        route_id=payload.route_id,
        method=payload.method,
        url=payload.url,
        principal_id=payload.principal_id,
        credential_id=payload.credential_ref,
        credential_version=payload.credential_version,
        policy_hash=payload.policy_hash,
        request_digest=payload.request_digest,
        operation_digest=payload.operation_digest,
        canonical_request=payload.canonical_request,
        redacted_display=redacted_display,
        pending_ttl_seconds=pending_ttl,
        grant_ttl_seconds=grant_ttl,
        grant_max_uses=max_uses,
    )
    return {
        "ok": True,
        **result,
        "approval_id": approval["id"],
        "approval_request_id": approval["id"],
        "expires_at": approval["expires_at"],
        "retry_after_seconds": 3,
    }


@app.post("/api/data-plane/rate-limits/consume")
def data_plane_rate_limit_consume(
    payload: DataPlaneRateLimitConsume,
    x_serverware_data_plane_token: str | None = Header(default=None, alias="X-Serverware-Data-Plane-Token"),
) -> dict[str, Any]:
    _require_data_plane_token(x_serverware_data_plane_token)
    try:
        result = db.consume_rate_limit(
            counter_key=payload.counter_key,
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            credential_id=payload.credential_ref or "",
            credential_version=payload.credential_version,
            policy_hash=payload.policy_hash,
            constraint_id=payload.constraint_id,
            operation=payload.operation,
            window_seconds=payload.window_seconds,
            max_count=payload.max_count,
            consume=payload.consume,
            actor_type="data-plane",
            actor_id=payload.actor_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
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
    cleared_rate_limit_counters = db.clear_rate_limit_counters(("demo.x.tweet.one_per_day",))
    db.record_audit_event(
        "demo.seeded",
        {
            "credential_id": credential["id"],
            "credential_version": credential.get("credential_version"),
            "secret_kek_id": credential.get("secret_kek_id"),
            "route_ids": [route["id"] for route in routes],
            "cleared_rate_limit_counters": cleared_rate_limit_counters,
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
    .hint { margin: 6px 0 0; color: var(--muted); font-size: 12px; line-height: 1.35; }
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
          <h2>OAuth Login</h2>
          <form id="oauth-form">
            <label>Provider</label>
            <select name="provider" id="oauth-provider"></select>
            <label>Credential name</label>
            <input name="credentialName" placeholder="Gmail OAuth - Andrew">
            <label>Scopes</label>
            <textarea name="scopes" id="oauth-scopes"></textarea>
            <label>Metadata JSON</label>
            <textarea name="metadata">{}</textarea>
            <p class="hint" id="oauth-status"></p>
            <label></label>
            <button type="submit">Login with OAuth</button>
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
            <div class="row">
              <div><label>Template</label><select id="route-template"></select></div>
              <div><label></label><button type="button" class="secondary" onclick="applyRouteTemplate()">Apply template</button></div>
            </div>
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
    let state = {credentials: [], routes: [], approvals: [], logs: [], ca_ready: false, oauthProviders: []};
    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const json = (value) => esc(JSON.stringify(value, null, 2));
    const tokenKey = 'serverware.adminToken';
    const routeTemplates = {
      gmail_recent: {
        label: 'Gmail last 30 days',
        name: 'Gmail recent mailbox',
        host: 'gmail.googleapis.com',
        path: '/gmail/v1',
        injection: {"type":"bearer","field":"access_token"},
        policies: [{"type":"gmail_recent","days":30,"max_results":10,"cache_ttl_seconds":1800}]
      },
      x_read_recent: {
        label: 'X recent search read',
        name: 'X recent search',
        host: 'api.x.com',
        path: '/2/tweets/search/recent',
        injection: {"type":"bearer","field":"access_token"},
        policies: [{"type":"operationPolicy","allowedOperations":["search.read"]},{"type":"queryDateWindow","parameters":["start_time","end_time"],"maxAgeDays":7},{"type":"queryNumericBounds","parameters":["max_results"],"min":1,"max":100,"integer":true}]
      },
      x_one_post_daily: {
        label: 'X one post daily',
        name: 'X one tweet per day',
        host: 'api.x.com',
        path: '/2/tweets',
        injection: {"type":"bearer","field":"access_token"},
        policies: [{"type":"operationPolicy","allowedOperations":["tweets.write"]},{"type":"rateLimit","max":1,"windowSeconds":86400,"store":"shared","key":{"scope":["principal","credential","route","operation"]}},{"type":"jsonBody","contentTypes":["application/json"],"allowedFields":["text","reply_settings"],"requiredFields":["text"],"deniedFields":["media","poll","direct_message_deep_link"],"fields":{"text":{"type":"string","minLength":1,"maxLength":280}}}]
      },
      npm_write_mfa: {
        label: 'npm write requires MFA',
        name: 'npm publish with JIT',
        host: 'registry.npmjs.org',
        path: '/',
        injection: {"type":"bearer"},
        policies: [{"type":"approval","ttl_seconds":30,"scope":"request_digest"}]
      },
      stripe_readonly: {
        label: 'Stripe customer read-only',
        name: 'Stripe read-only customers',
        host: 'api.stripe.com',
        path: '/v1/customers',
        injection: {"type":"bearer"},
        policies: [{"type":"queryNumericBounds","parameters":["limit"],"min":1,"max":25,"integer":true}]
      }
    };

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
      $('route-template').innerHTML = Object.entries(routeTemplates).map(([key, item]) => `<option value="${esc(key)}">${esc(item.label)}</option>`).join('');
      $('oauth-provider').innerHTML = (state.oauthProviders || []).map((item) => `<option value="${esc(item.id)}">${esc(item.displayName)}${item.configured ? '' : ' (not configured)'}</option>`).join('');
      renderOAuthDefaults();
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

    function renderOAuthDefaults() {
      const provider = (state.oauthProviders || []).find((item) => item.id === $('oauth-provider').value) || (state.oauthProviders || [])[0];
      if (!provider) {
        $('oauth-status').textContent = 'No OAuth providers configured.';
        return;
      }
      if (!$('oauth-scopes').value.trim()) $('oauth-scopes').value = (provider.defaultScopes || []).join('\\n');
      $('oauth-status').textContent = provider.configured ? `Redirect URI: ${provider.redirectUri}` : `Set OAuth client env vars for ${provider.displayName}.`;
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

    $('oauth-provider').addEventListener('change', () => {
      $('oauth-scopes').value = '';
      renderOAuthDefaults();
    });

    $('oauth-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.target);
      const scopes = String(form.get('scopes') || '').split(/[\\s,]+/).map((item) => item.trim()).filter(Boolean);
      const started = await api('/api/oauth/start', {method: 'POST', body: JSON.stringify({
        provider: form.get('provider'),
        credentialName: form.get('credentialName') || null,
        scopes,
        metadata: JSON.parse(form.get('metadata') || '{}')
      })});
      window.location.href = started.authorizationUrl;
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

    function applyRouteTemplate() {
      const item = routeTemplates[$('route-template').value];
      if (!item) return;
      const form = $('route-form');
      form.name.value = item.name;
      form.match_host.value = item.host;
      form.match_path_prefix.value = item.path;
      form.injection_type.value = item.injection.type || 'bearer';
      form.injection.value = JSON.stringify(item.injection, null, 2);
      form.policies.value = JSON.stringify(item.policies, null, 2);
    }

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
