from __future__ import annotations

import base64
import hmac
import html
import hashlib
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

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
    DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
    DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND,
    DEV_AUTHENTICATOR_ENABLED,
    DIRECT_CA_DOWNLOAD_ENABLED,
    EXPECTED_DATA_PLANE_BINARY_DIGEST,
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
    RELEASE_CHANNEL,
    SECRET_LEASE_TTL_SECONDS,
    WEBAUTHN_BOOTSTRAP_TOKEN,
)
from serverware import db, grants, runtime
from serverware.auth import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, AdminIdentity, admin_status, issue_csrf_cookie, require_admin, require_role, rotate_generated_admin_token, validate_csrf_request
from serverware.crypto import encrypt_credential_lease_envelope
from serverware.enrollment import AgentEnrollmentError, build_agent_enrollment, policy_principal_summaries
from serverware.key_release import KeyReleaseError, release_material, status as key_release_status
from serverware.oauth import (
    OAUTH_REFRESH_SKEW_SECONDS,
    OAuthError,
    create_authorization_url,
    exchange_authorization_code,
    provider_status,
    refresh_access_token,
    resolve_requested_scopes,
)
from serverware.policy_bundle import (
    PolicyBundleError,
    compile_policy_bundle,
    demo_policy_bundle,
    enforce_policy_high_water,
    get_policy_snapshot,
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
_credential_lease_audit_lock = threading.Lock()
_credential_lease_audit_last: dict[tuple[str, str, str, str, str, str, str], float] = {}
_CREDENTIAL_LEASE_AUDIT_INTERVAL_SECONDS = 60.0
_CREDENTIAL_LEASE_REQUEST_MAX_BYTES = 96 * 1024
_CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES = 4 * 1024 * 1024
_CREDENTIAL_LEASE_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
_SIGNED_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
_CONTROL_PLANE_REQUEST_MAX_BYTES = 2 * 1024 * 1024
_RECIPIENT_ATTESTATION_MAX_BYTES = 64 * 1024
_recipient_attestation_verifier_slots = threading.BoundedSemaphore(value=4)


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    try:
        validate_csrf_request(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
    return await call_next(request)


@app.middleware("http")
async def bounded_control_plane_request_middleware(request: Request, call_next):
    raw_content_length = request.headers.get("content-length")
    if raw_content_length is not None:
        try:
            content_length = int(raw_content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
        if content_length < 0:
            return JSONResponse(status_code=400, content={"detail": "invalid Content-Length"})
        if content_length > _CONTROL_PLANE_REQUEST_MAX_BYTES:
            return JSONResponse(status_code=413, content={"detail": "control-plane request exceeds 2 MiB"})
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > _CONTROL_PLANE_REQUEST_MAX_BYTES:
                return JSONResponse(status_code=413, content={"detail": "control-plane request exceeds 2 MiB"})
        request._body = bytes(body)
        request._stream_consumed = False
    return await call_next(request)


@app.middleware("http")
async def signed_response_middleware(request: Request, call_next):
    response = await call_next(request)
    body_buffer = bytearray()
    async for chunk in response.body_iterator:
        body_buffer.extend(chunk)
        if len(body_buffer) > _SIGNED_RESPONSE_MAX_BYTES:
            return JSONResponse(status_code=503, content={"detail": "signed response exceeds 8 MiB"})
    body = bytes(body_buffer)
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
    secret: str = Field(min_length=1, max_length=1_048_576)
    metadata: dict[str, Any] = Field(default_factory=dict)
    mfa: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return db.validate_credential_metadata(value)


class CredentialUpdate(BaseModel):
    name: str | None = None
    kind: str | None = None
    secret: str | None = Field(default=None, min_length=1, max_length=1_048_576)
    metadata: dict[str, Any] | None = None
    mfa: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else db.validate_credential_metadata(value)


class OAuthStartRequest(BaseModel):
    provider: str = Field(min_length=1)
    credential_name: str | None = Field(default=None, alias="credentialName")
    scopes: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    mfa: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return db.validate_credential_metadata(value)


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
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    activation_mode: str = Field(default="full", alias="activationMode", pattern="^(full|canary)$")
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
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    label: str = "YubiKey"
    bootstrap_token: str | None = Field(default=None, alias="bootstrapToken", max_length=1024)
    mfa: dict[str, Any] | None = None


class WebAuthnRegistrationFinish(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class CredentialLeaseRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    api_version: Literal["serverware.credentialLeaseRequest/v2"] = Field(alias="apiVersion")
    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_id: str = Field(alias="credentialId", min_length=1, max_length=256)
    recipient_public_key: str = Field(alias="recipientPublicKey", min_length=1, max_length=43)
    recipient_key_id: str = Field(alias="recipientKeyId", min_length=1, max_length=71)
    recipient_nonce: str = Field(alias="recipientNonce", min_length=1, max_length=43)
    policy_hash: str = Field(alias="policyHash", min_length=1, max_length=71)
    data_plane_binary_digest: str = Field(alias="dataPlaneBinaryDigest", min_length=1, max_length=71)
    max_ttl_seconds: int = Field(alias="maxTtlSeconds", ge=1, le=10)
    recipient_attestation: dict[str, Any] | None = Field(default=None, alias="recipientAttestation")

    @model_validator(mode="after")
    def validate_recipient_attestation_size(self) -> CredentialLeaseRequest:
        if self.recipient_attestation is None:
            return self
        try:
            encoded = json.dumps(
                self.recipient_attestation,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("recipient attestation must be canonical JSON") from exc
        if len(encoded) > _RECIPIENT_ATTESTATION_MAX_BYTES:
            raise ValueError("recipient attestation exceeds 64 KiB")
        return self


class DataPlaneGrantConsume(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    principal_id: str = Field(alias="principalId", min_length=1)
    route_id: str = Field(alias="routeId", min_length=1)
    credential_ref: str = Field(alias="credentialRef", min_length=1)
    credential_version: int = Field(alias="credentialVersion", ge=1)
    policy_hash: str = Field(alias="policyHash", min_length=1)
    request_digest: str = Field(alias="requestDigest", min_length=1)
    operation_digest: str | None = Field(default=None, alias="operationDigest")
    flow_id: str = Field(alias="flowId", min_length=1)
    attempt_id: str | None = Field(default=None, alias="attemptId", min_length=1, max_length=256)
    method: str = Field(default="UNKNOWN", min_length=1)
    url: str = Field(default="serverware://data-plane/jit", min_length=1)
    canonical_request: dict[str, Any] = Field(default_factory=dict, alias="canonicalRequest")
    redacted_display: dict[str, Any] = Field(default_factory=dict, alias="redactedDisplay")
    consume: bool = True


class DataPlaneRateLimitConsume(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    counter_key: str = Field(alias="counterKey", pattern=r"^sha256:[0-9a-f]{64}$")
    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_ref: str | None = Field(default=None, alias="credentialRef", max_length=256)
    credential_version: int = Field(alias="credentialVersion", ge=0)
    policy_hash: str = Field(alias="policyHash", pattern=r"^sha256:[0-9a-f]{64}$")
    constraint_id: str = Field(alias="constraintId", min_length=1, max_length=256)
    operation: str | None = Field(default=None, max_length=256)
    operation_context: dict[str, Any] = Field(default_factory=dict, alias="operationContext")
    max_count: int = Field(alias="max", ge=1, le=1_000_000_000)
    window_seconds: int = Field(alias="windowSeconds", ge=1, le=31_536_000)
    consume: bool = True
    actor_id: Literal["decision-gate-rs"] = Field(default="decision-gate-rs", alias="actorId")

    @model_validator(mode="after")
    def validate_operation_context_size(self) -> DataPlaneRateLimitConsume:
        try:
            encoded = json.dumps(
                self.operation_context,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("operationContext must be canonical JSON") from exc
        if len(encoded) > 16 * 1024:
            raise ValueError("operationContext exceeds 16 KiB")
        return self


class AgentEnrollmentCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal_id: str = Field(alias="principalId", min_length=1)
    proxy_url: str = Field(alias="proxyUrl", min_length=1)
    control_plane_url: str = Field(alias="controlPlaneUrl", min_length=1)
    proxy_egress_cidrs: list[str] = Field(alias="proxyEgressCidrs", min_length=1)
    namespace: str = "serverware-agents"
    pod_selector: dict[str, str] = Field(default_factory=dict, alias="podSelector")
    ca_mount_path: str = Field(default="/etc/serverware/serverware-ca.pem", alias="caMountPath")
    nonce: str = Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")
    ttl_seconds: int = Field(default=300, alias="ttlSeconds", ge=30, le=900)


class KeyReleaseVerify(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    material: str = Field(min_length=1)
    expected_policy_hash: str | None = Field(default=None, alias="expectedPolicyHash")
    expected_policy_sequence: int | None = Field(default=None, alias="expectedPolicySequence", ge=1)
    expected_policy_high_water_digest: str | None = Field(default=None, alias="expectedPolicyHighWaterDigest")
    expected_ca_spki: str | None = Field(default=None, alias="expectedCaSpki")
    expected_rollback_epoch: int | None = Field(default=None, alias="expectedRollbackEpoch")
    expected_release_channel: str | None = Field(default=None, alias="expectedReleaseChannel")
    expected_provenance_digest: str | None = Field(default=None, alias="expectedProvenanceDigest")
    expected_data_plane_binary_digest: str | None = Field(default=None, alias="expectedDataPlaneBinaryDigest")


@app.on_event("startup")
def startup() -> None:
    db.init_db()
    snapshot = get_policy_snapshot()
    if snapshot is not None:
        enforce_policy_high_water(snapshot)
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


def _approval_jit_policy(approval: dict[str, Any], *, require_current_policy: bool = False) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if require_current_policy and snapshot.hash != approval.get("policy_hash"):
        raise HTTPException(status_code=409, detail="active policy changed after approval request; request a new approval")
    route = _active_route_by_id(str(approval.get("route_id") or ""), snapshot=snapshot)
    return route.jit or {}


def _active_route_by_id(route_id: str, *, snapshot: Any | None = None) -> Any:
    snapshot = snapshot or get_policy_snapshot()
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


def _decode_unpadded_base64url(value: str, *, field_name: str, expected_length: int) -> bytes:
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise HTTPException(status_code=400, detail=f"{field_name} must be unpadded base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"{field_name} must be unpadded base64url") from exc
    if len(decoded) != expected_length:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must decode to exactly {expected_length} bytes",
        )
    if not hmac.compare_digest(base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("="), value):
        raise HTTPException(status_code=400, detail=f"{field_name} must use canonical base64url encoding")
    return decoded


async def _bounded_credential_lease_request(request: Request) -> CredentialLeaseRequest:
    _require_data_plane_token(request.headers.get("X-Serverware-Data-Plane-Token"))
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _CREDENTIAL_LEASE_REQUEST_MAX_BYTES:
                raise HTTPException(status_code=413, detail="credential lease request exceeds 96 KiB")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _CREDENTIAL_LEASE_REQUEST_MAX_BYTES:
            body.clear()
            raise HTTPException(status_code=413, detail="credential lease request exceeds 96 KiB")
    try:
        return CredentialLeaseRequest.model_validate_json(body)
    except ValidationError as exc:
        detail = [
            {key: error[key] for key in ("type", "loc", "msg") if key in error}
            for error in exc.errors(include_url=False, include_input=False)
        ]
        raise HTTPException(status_code=422, detail=detail) from exc


def _verify_credential_lease_recipient_attestation(
    evidence: dict[str, Any] | None,
    *,
    recipient_key_id: str,
    recipient_nonce: str,
    policy_hash_value: str,
    data_plane_binary_digest: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
) -> None:
    production_release = RELEASE_CHANNEL.strip().lower() not in {"dev", "development"}
    if production_release and (
        not DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED
        or not DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
    ):
        raise HTTPException(status_code=503, detail="production recipient attestation is not configured fail-closed")
    if evidence is None:
        if DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED:
            raise HTTPException(status_code=403, detail="recipient attestation is required")
        return
    if not DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND:
        raise HTTPException(status_code=503, detail="recipient attestation verifier is not configured")
    try:
        command = shlex.split(DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="recipient attestation verifier command is invalid") from exc
    if not command:
        raise HTTPException(status_code=503, detail="recipient attestation verifier is not configured")

    verifier_input = {
        "recipientAttestation": evidence,
        "recipientKeyId": recipient_key_id,
        "recipientNonce": recipient_nonce,
        "policyHash": policy_hash_value,
        "dataPlaneBinaryDigest": data_plane_binary_digest,
        "principalId": principal_id,
        "routeId": route_id,
        "credentialId": credential_id,
    }
    if not _recipient_attestation_verifier_slots.acquire(timeout=1.0):
        raise HTTPException(status_code=503, detail="recipient attestation verifier is at capacity")
    try:
        with tempfile.TemporaryFile() as verifier_stdin, tempfile.TemporaryFile() as verifier_stdout:
            verifier_stdin.write((_canonical_json(verifier_input) + "\n").encode("utf-8"))
            verifier_stdin.seek(0)
            verifier_env = {
                key: os.environ[key]
                for key in ("PATH", "LANG", "LC_ALL", "TZ")
                if key in os.environ
            }
            try:
                process = subprocess.Popen(
                    command,
                    stdin=verifier_stdin,
                    stdout=verifier_stdout,
                    stderr=subprocess.DEVNULL,
                    env=verifier_env,
                    start_new_session=True,
                )
            except OSError as exc:
                raise HTTPException(status_code=503, detail="recipient attestation verifier is unavailable") from exc
            deadline = time.monotonic() + 10.0
            while True:
                output_size = os.fstat(verifier_stdout.fileno()).st_size
                if output_size > _RECIPIENT_ATTESTATION_MAX_BYTES:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        process.kill()
                    process.wait()
                    raise HTTPException(
                        status_code=503,
                        detail="recipient attestation verifier output exceeds 64 KiB",
                    )
                return_code = process.poll()
                if return_code is not None:
                    break
                if time.monotonic() >= deadline:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        process.kill()
                    process.wait()
                    raise HTTPException(status_code=503, detail="recipient attestation verifier timed out")
                time.sleep(0.005)
            if return_code != 0:
                raise HTTPException(status_code=403, detail="recipient attestation verification failed")
            verifier_stdout.seek(0)
            verifier_output = verifier_stdout.read(_RECIPIENT_ATTESTATION_MAX_BYTES + 1)
    finally:
        _recipient_attestation_verifier_slots.release()
    try:
        verified = json.loads(verifier_output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="recipient attestation verifier returned invalid JSON") from exc
    if not isinstance(verified, dict):
        raise HTTPException(status_code=503, detail="recipient attestation verifier returned invalid JSON")
    if verified.get("ok") is not True:
        raise HTTPException(status_code=403, detail="recipient attestation verification failed")
    expected_bindings = {
        "recipientKeyId": recipient_key_id,
        "recipientNonce": recipient_nonce,
        "policyHash": policy_hash_value,
        "dataPlaneBinaryDigest": data_plane_binary_digest,
        "principalId": principal_id,
        "routeId": route_id,
        "credentialId": credential_id,
    }
    if any(
        not isinstance(verified.get(field), str)
        or not hmac.compare_digest(verified[field], expected)
        for field, expected in expected_bindings.items()
    ):
        raise HTTPException(status_code=403, detail="recipient attestation binding mismatch")
    if RELEASE_CHANNEL.strip().lower() not in {"dev", "development"} and verified.get("debug") is not False:
        raise HTTPException(status_code=403, detail="debug recipient attestation is not allowed for this release channel")


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
        raise HTTPException(
            status_code=412,
            detail={
                "error": "control_plane_webauthn_required",
                "message": "WebAuthn assertion required for control-plane mutation",
                "action": action,
                "resourceId": resource_id,
                "payloadDigest": payload_digest,
            },
        )
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
            expected_policy_sequence=payload.expected_policy_sequence,
            expected_policy_high_water_digest=payload.expected_policy_high_water_digest,
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
    can_view_credentials = identity.has_any_role({"policy_author", "credential_owner"})
    can_view_routes = identity.has_any_role({"policy_author", "policy_publisher", "auditor"})
    can_view_approvals = identity.has_any_role({"approver", "auditor"})
    can_view_logs = identity.has_any_role({"auditor"})
    credentials = db.list_credentials() if can_view_credentials else []
    routes = db.list_routes() if can_view_routes else []
    approvals = db.list_approvals(limit=100) if can_view_approvals else []
    logs = db.list_logs(limit=150) if can_view_logs else []
    policy_principals = (
        policy_principal_summaries(snapshot)
        if snapshot is not None and can_view_routes
        else []
    )
    webauthn_credential_count = len(db.list_webauthn_credentials(identity.user_id))
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
        "policyPrincipals": policy_principals,
        "oauthProviders": provider_status() if can_view_credentials else [],
        "webauthnCredentialCount": webauthn_credential_count,
        "webauthnBootstrapRequired": (
            webauthn_credential_count == 0
            and RELEASE_CHANNEL.strip().lower() not in {"dev", "development", "local", "test"}
        ),
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
                "webauthn_credentials": webauthn_credential_count,
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
    snapshot = write_policy_bundle(report["signedBundle"], enforce_high_water=True)
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
        return {"ok": True, "canary": None, "monitoring": None}
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
    snapshot = write_policy_bundle(signed_bundle, enforce_high_water=True)
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
            attestation=attestation_document(payload.nonce),
            proxy_url=payload.proxy_url,
            control_plane_url=payload.control_plane_url,
            proxy_egress_cidrs=payload.proxy_egress_cidrs,
            namespace=payload.namespace,
            pod_selector=payload.pod_selector,
            ca_mount_path=payload.ca_mount_path,
            nonce=payload.nonce,
            ttl_seconds=payload.ttl_seconds,
        )
    except AgentEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/oauth/providers")
def oauth_providers(_: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner"))) -> dict[str, Any]:
    return {"providers": provider_status()}


def _canonical_oauth_granted_scopes(raw_scopes: Any, *, field_name: str = "OAuth granted scopes") -> tuple[str, ...]:
    if not isinstance(raw_scopes, list) or not raw_scopes:
        raise OAuthError(f"{field_name} must be a non-empty array")
    scopes: list[str] = []
    for scope in raw_scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or any(character.isspace() for character in scope)
        ):
            raise OAuthError(f"{field_name} contains an invalid scope")
        scopes.append(scope)
    if len(scopes) > 30 or any(len(scope) > 200 for scope in scopes):
        raise OAuthError(f"{field_name} is too large")
    if len(scopes) != len(set(scopes)):
        raise OAuthError(f"{field_name} contains duplicate scopes")
    return tuple(sorted(scopes))


@app.post("/api/oauth/start")
def oauth_start(
    payload: OAuthStartRequest,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author", "credential_owner")),
) -> dict[str, Any]:
    try:
        requested_scopes = list(resolve_requested_scopes(payload.provider, payload.scopes))
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    mutation_payload = payload.model_dump(exclude={"mfa"})
    mutation_payload["scopes"] = requested_scopes
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
            "scopes": requested_scopes,
            "metadata_keys": sorted(payload.metadata),
        },
    )
    try:
        started = create_authorization_url(
            provider_id=payload.provider,
            credential_name=payload.credential_name,
            scopes=requested_scopes,
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
        if not isinstance(exchanged, dict):
            raise OAuthError("OAuth token exchange result is malformed")
        granted_scopes = _canonical_oauth_granted_scopes(exchanged.get("scopes"))
        credential_metadata = exchanged.get("metadata")
        if not isinstance(credential_metadata, dict):
            raise OAuthError("OAuth credential metadata is malformed")
        metadata_scopes = _canonical_oauth_granted_scopes(
            credential_metadata.get("scopes"),
            field_name="OAuth credential metadata scopes",
        )
        if metadata_scopes != granted_scopes:
            raise OAuthError("OAuth credential metadata does not match the provider-granted scopes")
        credential_metadata = {**credential_metadata, "scopes": list(granted_scopes)}
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
        credential_metadata,
    )
    runtime.invalidate_secret_leases(credential["id"])
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
            "provider_account": exchanged.get("providerAccount"),
            "provider_subject": exchanged.get("providerSubject"),
            "provider_identity_verified": True,
            "scopes": list(granted_scopes),
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
    if payload.kind == "oauth2" or payload.metadata.get("oauth") is True:
        raise HTTPException(
            status_code=409,
            detail="managed OAuth credentials must be created through the verified provider connection flow",
        )
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
    runtime.invalidate_secret_leases(created["id"])
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
    try:
        updated = db.update_credential(credential_id, changes)
    except db.ManagedOAuthCredentialError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
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
    runtime.invalidate_secret_leases(credential_id)
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
        runtime.invalidate_secret_leases(credential_id)
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
    jit = _approval_jit_policy(approval, require_current_policy=True)
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
    jit = _approval_jit_policy(approval, require_current_policy=True)
    _assert_approver_allowed(identity, jit)
    return approval_options(approval, identity.user_id, _approval_authn_policy(jit))


@app.post("/api/webauthn/register/options")
def webauthn_register_options(
    payload: WebAuthnRegistrationStart,
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> dict[str, Any]:
    existing = db.list_webauthn_credentials(identity.user_id)
    production_release = RELEASE_CHANNEL.strip().lower() not in {"dev", "development", "local", "test"}
    payload_digest = _control_plane_payload_digest(
        {
            "user_id": identity.user_id,
            "label": payload.label,
            "existing_credential_ids": sorted(str(item["credential_id"]) for item in existing),
        }
    )
    if not existing:
        if production_release:
            if len(WEBAUTHN_BOOTSTRAP_TOKEN) < 32:
                raise HTTPException(status_code=503, detail="WebAuthn bootstrap token is not configured safely")
            if not payload.bootstrap_token or not hmac.compare_digest(WEBAUTHN_BOOTSTRAP_TOKEN, payload.bootstrap_token):
                raise HTTPException(status_code=403, detail="valid WebAuthn bootstrap token required for first enrollment")
        authorization = {
            "mode": "bootstrap-token" if production_release else "development-bootstrap",
            "payload_digest": payload_digest,
            "existing_credential_count": 0,
        }
    else:
        mfa = _require_control_plane_mutation_mfa(
            action="webauthn.credential.register",
            resource_id=identity.user_id,
            payload_digest=payload_digest,
            mfa=payload.mfa,
            identity=identity,
        )
        two_person = _require_control_plane_two_person(
            action="webauthn.credential.register",
            resource_id=identity.user_id,
            payload_digest=payload_digest,
            mfa=payload.mfa,
            identity=identity,
            request={"user_id": identity.user_id, "label": payload.label, "existing_credential_count": len(existing)},
        )
        authorization = {
            "mode": "existing-webauthn",
            "payload_digest": payload_digest,
            "existing_credential_count": len(existing),
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
        }
    return registration_options(identity.user_id, payload.label, authorization=authorization)


@app.post("/api/webauthn/register/verify")
def webauthn_register_verify(
    payload: WebAuthnRegistrationFinish,
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> dict[str, Any]:
    try:
        credential = verify_registration(
            identity.user_id,
            payload.label,
            payload.response,
            require_authorization=True,
        )
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
            "registration_authorization": credential.pop("_registration_authorization", None),
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


def _record_credential_lease_audit(
    outcome: str,
    payload: CredentialLeaseRequest,
    *,
    authenticated: bool,
    status_code: int,
    reason: str | None = None,
    credential_ids: list[str] | None = None,
    issued_at_epoch_ms: int | None = None,
    expires_at_epoch_ms: int | None = None,
) -> None:
    event = {
        "outcome": outcome,
        "status_code": status_code,
        "reason": reason,
        "recipient_key_id": payload.recipient_key_id,
        "recipient_nonce_sha256": "sha256:"
        + hashlib.sha256(payload.recipient_nonce.encode("ascii", errors="replace")).hexdigest(),
        "policy_hash": payload.policy_hash,
        "data_plane_binary_digest": payload.data_plane_binary_digest,
        "principal_id": payload.principal_id,
        "route_id": payload.route_id,
        "credential_id": payload.credential_id,
        "requested_max_ttl_seconds": payload.max_ttl_seconds,
        "recipient_attestation_present": payload.recipient_attestation is not None,
        "credential_count": len(credential_ids or []),
        "credential_ids": credential_ids or [],
        "issued_at_epoch_ms": issued_at_epoch_ms,
        "expires_at_epoch_ms": expires_at_epoch_ms,
    }
    db.record_audit_event(
        f"data_plane.credential_lease.{outcome}",
        event,
        actor_type="data-plane",
        actor_id=payload.recipient_key_id if authenticated else None,
    )


def _should_record_credential_lease_issuance(
    payload: CredentialLeaseRequest,
    credentials: list[dict[str, Any]],
) -> tuple[str, str, str, str, str, str, str] | None:
    state_digest = "sha256:" + hashlib.sha256(
        _canonical_json(
            [
                [item["credentialId"], int(item["credentialVersion"])]
                for item in credentials
            ]
        ).encode("utf-8")
    ).hexdigest()
    key = (
        payload.recipient_key_id,
        payload.policy_hash,
        payload.data_plane_binary_digest,
        payload.principal_id,
        payload.route_id,
        payload.credential_id,
        state_digest,
    )
    now = time.monotonic()
    with _credential_lease_audit_lock:
        expired = [
            item
            for item, last_recorded in _credential_lease_audit_last.items()
            if last_recorded + _CREDENTIAL_LEASE_AUDIT_INTERVAL_SECONDS <= now
        ]
        for item in expired:
            _credential_lease_audit_last.pop(item, None)
        if key in _credential_lease_audit_last:
            return None
        _credential_lease_audit_last[key] = now
    return key


def _credential_for_lease(credential_id: str) -> dict[str, Any] | None:
    credential: dict[str, Any] | None = None
    provider_id: str | None = None
    try:
        for _ in range(2):
            credential = runtime.get_credential(credential_id)
            if not credential or credential.get("kind") != "oauth2":
                return credential
            metadata = credential.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("oauth") is not True:
                return credential
            expires_at_epoch_ms = metadata.get("expires_at_epoch_ms")
            if not isinstance(expires_at_epoch_ms, int) or isinstance(expires_at_epoch_ms, bool):
                raise OAuthError("managed OAuth credential has no valid access-token expiry")
            now_epoch_ms = time.time_ns() // 1_000_000
            if expires_at_epoch_ms > now_epoch_ms + OAUTH_REFRESH_SKEW_SECONDS * 1000:
                return credential
            provider_id = metadata.get("provider_id")
            if not isinstance(provider_id, str) or not provider_id:
                raise OAuthError("managed OAuth credential has no provider binding")

            with db.oauth_refresh_lock(credential_id):
                runtime.invalidate_secret_leases(credential_id)
                credential = runtime.get_credential(credential_id)
                if not credential:
                    return None
                metadata = credential.get("metadata")
                if credential.get("kind") != "oauth2" or not isinstance(metadata, dict) or metadata.get("oauth") is not True:
                    return credential
                provider_id = metadata.get("provider_id")
                if not isinstance(provider_id, str) or not provider_id:
                    raise OAuthError("managed OAuth credential has no provider binding")
                expires_at_epoch_ms = metadata.get("expires_at_epoch_ms") if isinstance(metadata, dict) else None
                now_epoch_ms = time.time_ns() // 1_000_000
                if (
                    isinstance(expires_at_epoch_ms, int)
                    and not isinstance(expires_at_epoch_ms, bool)
                    and expires_at_epoch_ms > now_epoch_ms + OAUTH_REFRESH_SKEW_SECONDS * 1000
                ):
                    return credential
                token_secret = json.loads(str(credential.get("secret") or ""))
                refreshed = refresh_access_token(
                    provider_id=provider_id,
                    token_secret=token_secret,
                    metadata=metadata,
                    now_epoch=now_epoch_ms // 1000,
                )
                if not isinstance(refreshed, dict):
                    raise OAuthError("OAuth refresh result is malformed")
                refreshed_scopes = _canonical_oauth_granted_scopes(refreshed.get("scopes"))
                refreshed_metadata = refreshed.get("metadata")
                if not isinstance(refreshed_metadata, dict):
                    raise OAuthError("OAuth refresh credential metadata is malformed")
                refreshed_metadata_scopes = _canonical_oauth_granted_scopes(
                    refreshed_metadata.get("scopes"),
                    field_name="OAuth refresh credential metadata scopes",
                )
                if refreshed_metadata_scopes != refreshed_scopes:
                    raise OAuthError("OAuth refresh metadata does not match the provider-granted scopes")
                refreshed_metadata = {**refreshed_metadata, "scopes": list(refreshed_scopes)}
                persisted, rotated = db.update_credential_secret_if_version(
                    credential_id,
                    expected_version=int(credential.get("credential_version") or 0),
                    secret=refreshed["secret"],
                    metadata=refreshed_metadata,
                )
                if not persisted:
                    raise OAuthError("OAuth credential disappeared during refresh")
                if not rotated:
                    runtime.invalidate_secret_leases(credential_id)
                    continue
                runtime.invalidate_secret_leases(credential_id)
                db.record_audit_event(
                    "credential.oauth_refreshed",
                    {
                        "credential_id": credential_id,
                        "provider": provider_id,
                        "previous_credential_version": credential.get("credential_version"),
                        "credential_version": persisted.get("credential_version"),
                        "expires_at_epoch_ms": refreshed["expiresAtEpochMs"],
                        "refresh_token_rotated": refreshed["refreshTokenRotated"],
                        "scopes": list(refreshed_scopes),
                    },
                    actor_type="system",
                    actor_id="oauth-refresh",
                )
                return persisted
        raise OAuthError("OAuth credential changed repeatedly during refresh")
    except (OAuthError, ValueError, TypeError, json.JSONDecodeError) as exc:
        try:
            db.record_audit_event(
                "credential.oauth_refresh_failed",
                {
                    "credential_id": credential_id,
                    "provider": provider_id,
                    "credential_version": credential.get("credential_version"),
                    "reason": type(exc).__name__,
                },
                actor_type="system",
                actor_id="oauth-refresh",
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=503,
            detail="OAuth access token could not be refreshed; reconnect the provider account",
        ) from exc


def _normalized_credential_provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    aliases = {
        "twitter": "x",
        "x.oauth2": "x",
        "google.oauth2": "google",
    }
    return aliases.get(provider, provider)


def _credential_metadata_scopes(metadata: dict[str, Any]) -> frozenset[str]:
    raw_scopes = metadata.get("scopes")
    if raw_scopes is None:
        raw_scopes = metadata.get("scope")
    if raw_scopes is None:
        return frozenset()
    if isinstance(raw_scopes, str):
        scopes = [item for item in raw_scopes.split() if item]
    elif isinstance(raw_scopes, list) and all(isinstance(item, str) and item for item in raw_scopes):
        scopes = raw_scopes
    else:
        raise HTTPException(status_code=503, detail="credential scope metadata is invalid")
    if len(scopes) != len(set(scopes)):
        raise HTTPException(status_code=503, detail="credential scope metadata contains duplicates")
    return frozenset(scopes)


def _assert_credential_policy_binding(credential: dict[str, Any], credential_policy: Any) -> None:
    metadata = credential.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=503, detail="credential metadata is invalid")
    policy_provider = _normalized_credential_provider(credential_policy.provider)
    stored_provider = _normalized_credential_provider(metadata.get("provider_id") or metadata.get("provider"))
    if policy_provider not in {"", "generic"} and stored_provider != policy_provider:
        raise HTTPException(
            status_code=409,
            detail="stored credential provider does not match the active signed policy",
        )
    if credential_policy.provider_subject is not None and credential.get("kind") != "oauth2":
        raise HTTPException(
            status_code=409,
            detail="signed provider account binding requires a verified OAuth credential",
        )
    if credential.get("kind") == "oauth2":
        try:
            verified_provider, stored_subject = db.validate_managed_oauth_identity(metadata)
        except db.ManagedOAuthCredentialError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if _normalized_credential_provider(verified_provider) != policy_provider:
            raise HTTPException(
                status_code=409,
                detail="verified OAuth provider does not match the active signed policy",
            )
        policy_subject = credential_policy.provider_subject
        if (
            not isinstance(policy_subject, str)
            or not policy_subject
            or stored_subject != policy_subject
        ):
            raise HTTPException(
                status_code=409,
                detail="stored OAuth account does not match the active signed policy",
            )
        try:
            stored_scopes = frozenset(
                _canonical_oauth_granted_scopes(
                    metadata.get("scopes"),
                    field_name="OAuth credential metadata scopes",
                )
            )
            policy_scopes = frozenset(
                _canonical_oauth_granted_scopes(
                    list(credential_policy.scopes),
                    field_name="signed policy OAuth scopes",
                )
            )
        except OAuthError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    else:
        policy_scopes = frozenset(str(item) for item in credential_policy.scopes)
        stored_scopes = _credential_metadata_scopes(metadata)
    if credential.get("kind") == "oauth2" and stored_scopes != policy_scopes:
        raise HTTPException(
            status_code=409,
            detail="stored OAuth scopes do not exactly match the active signed policy",
        )
    if credential.get("kind") != "oauth2" and not stored_scopes.issubset(policy_scopes):
        raise HTTPException(
            status_code=409,
            detail="stored credential scopes exceed the active signed policy",
        )


def _assert_credential_lease_route_binding(payload: CredentialLeaseRequest, snapshot: Any) -> Any:
    if not hmac.compare_digest(snapshot.hash, payload.policy_hash):
        raise HTTPException(status_code=409, detail="data-plane policy hash is not active")
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(status_code=409, detail="principal is not assigned to the requested active route")
    if route.credential_ref is None or not hmac.compare_digest(route.credential_ref, payload.credential_id):
        raise HTTPException(status_code=409, detail="credential does not match the requested active route")
    credential_policy = snapshot.credentials.get(payload.credential_id)
    if credential_policy is None:
        raise HTTPException(status_code=409, detail="credential is not declared by the active policy")
    return credential_policy


@app.post("/api/data-plane/credential-leases")
def data_plane_credential_leases(
    payload: CredentialLeaseRequest = Depends(_bounded_credential_lease_request),
) -> Response:
    authenticated = True
    try:
        snapshot = get_policy_snapshot()
        if not snapshot:
            raise HTTPException(status_code=503, detail="active signed policy bundle is unavailable")
        credential_policy = _assert_credential_lease_route_binding(payload, snapshot)
        if not EXPECTED_DATA_PLANE_BINARY_DIGEST:
            raise HTTPException(status_code=503, detail="expected data-plane binary digest is not configured")
        if not hmac.compare_digest(EXPECTED_DATA_PLANE_BINARY_DIGEST, payload.data_plane_binary_digest):
            raise HTTPException(status_code=409, detail="data-plane binary digest does not match configured digest")

        recipient_public_key = _decode_unpadded_base64url(
            payload.recipient_public_key,
            field_name="recipientPublicKey",
            expected_length=32,
        )
        recipient_nonce = _decode_unpadded_base64url(
            payload.recipient_nonce,
            field_name="recipientNonce",
            expected_length=32,
        )
        expected_recipient_key_id = "sha256:" + hashlib.sha256(recipient_public_key).hexdigest()
        if not hmac.compare_digest(expected_recipient_key_id, payload.recipient_key_id):
            raise HTTPException(status_code=400, detail="recipientKeyId does not match recipientPublicKey")
        issued_at_epoch_ms = time.time_ns() // 1_000_000
        replay_result = db.reserve_credential_lease_nonce(
            payload.recipient_key_id,
            "sha256:" + hashlib.sha256(recipient_nonce).hexdigest(),
            now_epoch_ms=issued_at_epoch_ms,
        )
        if replay_result == "replay":
            raise HTTPException(status_code=409, detail="recipient nonce has already been used")
        if replay_result == "capacity":
            raise HTTPException(status_code=503, detail="credential lease replay cache is at capacity")
        _verify_credential_lease_recipient_attestation(
            payload.recipient_attestation,
            recipient_key_id=expected_recipient_key_id,
            recipient_nonce=payload.recipient_nonce,
            policy_hash_value=snapshot.hash,
            data_plane_binary_digest=EXPECTED_DATA_PLANE_BINARY_DIGEST,
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            credential_id=payload.credential_id,
        )
        if not (SECRET_LEASE_TTL_SECONDS > 0):
            raise HTTPException(status_code=503, detail="credential lease TTL is not configured safely")

        ttl_ms = max(1, int(min(float(payload.max_ttl_seconds), SECRET_LEASE_TTL_SECONDS, 10.0) * 1000))
        expires_at_epoch_ms = issued_at_epoch_ms + ttl_ms

        credential = _credential_for_lease(payload.credential_id)
        if not credential:
            raise HTTPException(status_code=404, detail="requested credential is unavailable")
        _assert_credential_policy_binding(credential, credential_policy)

        current_snapshot = get_policy_snapshot()
        if current_snapshot is None:
            raise HTTPException(status_code=503, detail="active signed policy bundle became unavailable")
        current_credential_policy = _assert_credential_lease_route_binding(payload, current_snapshot)
        with db.credential_lease_snapshot(payload.credential_id) as current_credential:
            if not current_credential:
                raise HTTPException(status_code=404, detail="requested credential became unavailable")
            if int(current_credential.get("credential_version") or 0) != int(credential.get("credential_version") or 0):
                raise HTTPException(status_code=409, detail="credential changed during lease authorization")
            _assert_credential_policy_binding(current_credential, current_credential_policy)
            credential = current_credential
            metadata = credential.get("metadata") or {}
            credentials = [
                {
                    "credentialId": payload.credential_id,
                    "credentialVersion": int(credential["credential_version"]),
                    "secret": str(credential["secret"]),
                    "metadata": metadata,
                }
            ]

            aad = {
                "apiVersion": "serverware.credentialLeaseEnvelope/v2",
                "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
                "recipientKeyId": payload.recipient_key_id,
                "recipientNonce": payload.recipient_nonce,
                "policyHash": payload.policy_hash,
                "dataPlaneBinaryDigest": payload.data_plane_binary_digest,
                "principalId": payload.principal_id,
                "routeId": payload.route_id,
                "credentialId": payload.credential_id,
                "issuedAtEpochMs": issued_at_epoch_ms,
                "expiresAtEpochMs": expires_at_epoch_ms,
            }
            plaintext = {
                "apiVersion": "serverware.credentialLeaseSet/v2",
                "recipientKeyId": payload.recipient_key_id,
                "recipientNonce": payload.recipient_nonce,
                "policyHash": payload.policy_hash,
                "dataPlaneBinaryDigest": payload.data_plane_binary_digest,
                "principalId": payload.principal_id,
                "routeId": payload.route_id,
                "credentialId": payload.credential_id,
                "issuedAtEpochMs": issued_at_epoch_ms,
                "expiresAtEpochMs": expires_at_epoch_ms,
                "credentials": credentials,
            }
            if len(_canonical_json(plaintext).encode("utf-8")) > _CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES:
                raise HTTPException(status_code=503, detail="credential lease plaintext exceeds 4 MiB")
            try:
                encrypted = encrypt_credential_lease_envelope(
                    recipient_public_key=recipient_public_key,
                    recipient_nonce=recipient_nonce,
                    aad=aad,
                    plaintext=plaintext,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="recipientPublicKey is not a valid X25519 public key") from exc
            response_body = _canonical_json({**aad, **encrypted}).encode("utf-8")
            if len(response_body) > _CREDENTIAL_LEASE_RESPONSE_MAX_BYTES:
                raise HTTPException(status_code=503, detail="credential lease response exceeds 8 MiB")
    except HTTPException as exc:
        _record_credential_lease_audit(
            "rejected",
            payload,
            authenticated=authenticated,
            status_code=exc.status_code,
            reason=str(exc.detail),
        )
        raise
    except Exception as exc:
        _record_credential_lease_audit(
            "rejected",
            payload,
            authenticated=authenticated,
            status_code=503,
            reason="credential lease issuance failed",
        )
        raise HTTPException(status_code=503, detail="credential lease issuance failed") from exc

    issuance_audit_key = _should_record_credential_lease_issuance(payload, credentials)
    if issuance_audit_key is not None:
        try:
            _record_credential_lease_audit(
                "issued",
                payload,
                authenticated=True,
                status_code=200,
                credential_ids=[item["credentialId"] for item in credentials],
                issued_at_epoch_ms=issued_at_epoch_ms,
                expires_at_epoch_ms=expires_at_epoch_ms,
            )
        except Exception as exc:
            with _credential_lease_audit_lock:
                _credential_lease_audit_last.pop(issuance_audit_key, None)
            raise HTTPException(status_code=503, detail="credential lease issuance audit is unavailable") from exc
    return Response(
        content=response_body,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


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
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if snapshot.hash != payload.policy_hash:
        raise HTTPException(status_code=409, detail="data-plane policy hash is not active")
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(status_code=409, detail="data-plane principal is not assigned to active route")
    if route.credential_ref and route.credential_ref != payload.credential_ref:
        raise HTTPException(status_code=409, detail="data-plane credential reference does not match active route")
    grant_args = {
        "principal_id": payload.principal_id,
        "route_id": payload.route_id,
        "credential_id": payload.credential_ref,
        "credential_version": payload.credential_version,
        "policy_hash": payload.policy_hash,
        "request_digest": payload.request_digest,
        "operation_digest": payload.operation_digest,
    }
    result = (
        db.consume_jit_grant_result(
            **grant_args,
            flow_id=payload.flow_id,
            attempt_id=payload.attempt_id or payload.flow_id,
        )
        if payload.consume
        else db.find_jit_grant_result(**grant_args)
    )
    if result.get("consumed") or result.get("available"):
        return {"ok": True, **result}
    if result.get("reason") == "grant_locked_retry":
        raise HTTPException(
            status_code=503,
            detail="grant state is busy; retry this attempt",
            headers={"Retry-After": "1"},
        )
    if result.get("reason") == "attempt_id_conflict":
        raise HTTPException(status_code=409, detail="grant attempt id was already bound to a different request")
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
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if not hmac.compare_digest(snapshot.hash, payload.policy_hash):
        raise HTTPException(status_code=409, detail="data-plane policy hash is not active")
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(status_code=409, detail="data-plane principal is not assigned to active route")
    expected_credential_ref = route.credential_ref or ""
    if not hmac.compare_digest(payload.credential_ref or "", expected_credential_ref):
        raise HTTPException(status_code=409, detail="data-plane credential reference does not match active route")
    if expected_credential_ref:
        credential = db.get_credential(expected_credential_ref)
        if not credential or int(credential.get("credential_version") or 0) != payload.credential_version:
            raise HTTPException(status_code=409, detail="data-plane credential version is not current")
    elif payload.credential_version != 0:
        raise HTTPException(status_code=409, detail="credential-less route must use credential version zero")
    matching_constraints = [
        item
        for item in route.constraints
        if item.get("id") == payload.constraint_id and item.get("type") == "rateLimit"
    ]
    if len(matching_constraints) != 1 or matching_constraints[0].get("store", "local") != "shared":
        raise HTTPException(status_code=409, detail="shared rate-limit constraint is not active on the route")
    constraint = matching_constraints[0]
    expected_max = int(constraint["max"])
    expected_window_seconds = int(constraint["windowSeconds"])
    if payload.max_count != expected_max or payload.window_seconds != expected_window_seconds:
        raise HTTPException(status_code=409, detail="shared rate-limit parameters do not match active policy")
    operation_context = dict(payload.operation_context)
    operation_name = operation_context.get("operation")
    if not isinstance(operation_name, str):
        operation_name = ""
    if (payload.operation or "") != operation_name:
        raise HTTPException(status_code=409, detail="shared rate-limit operation does not match operationContext")
    expected_counter_key = _rate_limit_counter_key(
        constraint=constraint,
        route_id=route.id,
        principal_id=payload.principal_id,
        credential_ref=route.credential_ref,
        credential_version=payload.credential_version,
        operation_context=operation_context,
    )
    if not hmac.compare_digest(payload.counter_key, expected_counter_key):
        raise HTTPException(status_code=409, detail="shared rate-limit counter key does not match active policy")
    try:
        result = db.consume_rate_limit(
            counter_key=expected_counter_key,
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            credential_id=payload.credential_ref or "",
            credential_version=payload.credential_version,
            policy_hash=payload.policy_hash,
            constraint_id=payload.constraint_id,
            operation=operation_name,
            window_seconds=expected_window_seconds,
            max_count=expected_max,
            consume=payload.consume,
            actor_type="data-plane",
            actor_id="decision-gate-rs",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"ok": True, **result}


def _rate_limit_counter_key(
    *,
    constraint: dict[str, Any],
    route_id: str,
    principal_id: str,
    credential_ref: str | None,
    credential_version: int,
    operation_context: dict[str, Any],
) -> str:
    key_policy = constraint.get("key") or {}
    scope = key_policy.get("scope") or ["principal", "credential", "route", "operation"]
    material: dict[str, Any] = {"constraint": str(constraint.get("id") or "unnamed")}
    for item in scope:
        if item == "principal":
            material[item] = principal_id
        elif item == "credential":
            material[item] = credential_ref or ""
        elif item == "credentialVersion":
            material[item] = credential_version
        elif item == "route":
            material[item] = route_id
        elif item == "operation":
            value = operation_context.get("operation")
            material[item] = value if isinstance(value, str) else ""
    for field in key_policy.get("operationFields") or []:
        value = operation_context.get(field)
        material[f"operation.{field}"] = value if isinstance(value, str) else ""
    return "sha256:" + hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


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
            "high_water": db.get_policy_high_water(),
        }
    metadata = snapshot.raw.get("metadata") or {}
    return {
        "ready": True,
        "policy_hash": snapshot.hash,
        "policy_path": str(POLICY_BUNDLE_PATH),
        "metadata": metadata,
        "bundle": snapshot.raw,
        "public_key_pem": policy_public_key_pem(),
        "high_water": db.get_policy_high_water(),
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
    if not DEV_AUTHENTICATOR_ENABLED:
        raise HTTPException(status_code=404, detail="not found")
    current_snapshot = get_policy_snapshot()
    bundle = demo_policy_bundle("cred-demo-bearer")
    high_water = db.get_policy_high_water()
    next_sequence = int(bundle["metadata"]["sequence"])
    next_rollback_epoch = int(bundle["metadata"]["rollbackEpoch"])
    if current_snapshot is not None:
        current_metadata = current_snapshot.raw.get("metadata") or {}
        next_sequence = max(next_sequence, int(current_metadata.get("sequence") or 0) + 1)
        next_rollback_epoch = max(
            next_rollback_epoch,
            int(current_metadata.get("rollbackEpoch") or 0),
        )
    if high_water is not None:
        if high_water["policy_id"] != bundle["metadata"]["id"]:
            raise HTTPException(status_code=409, detail="demo policy id conflicts with persisted high-water state")
        next_sequence = max(next_sequence, int(high_water["sequence"]) + 1)
        next_rollback_epoch = max(next_rollback_epoch, int(high_water["rollback_epoch"]))
    bundle["metadata"]["sequence"] = next_sequence
    bundle["metadata"]["rollbackEpoch"] = next_rollback_epoch
    policy_snapshot = write_policy_bundle(bundle, enforce_high_water=True)
    credential = db.upsert_credential_with_id(
        "cred-demo-bearer",
        "Demo bearer token",
        "bearer",
        "demo-token-from-vault",
        {
            "x_app_id": "demo-x-app",
            "managed": True,
            "provider_id": "demo",
            "scopes": ["demo"],
            "expires_at_epoch_ms": 4_102_444_800_000,
        },
    )
    runtime.invalidate_secret_leases(credential["id"])
    common = {
        "enabled": True,
        "match_host": "demo-upstream",
        "credential_id": credential["id"],
        "injection": {"type": "bearer"},
    }
    credentialless_stream = {
        "enabled": True,
        "match_host": "demo-upstream",
        "credential_id": None,
        "injection": {},
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
                **credentialless_stream,
                "name": "Demo streaming upload",
                "match_path_prefix": "/upload-bytes",
                "policies": [{"type": "request_body_stream", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.jsonl.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSONL streaming redaction",
                "match_path_prefix": "/jsonl-redact",
                "policies": [{"type": "jsonl_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.array.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSON array streaming redaction",
                "match_path_prefix": "/json-array-redact",
                "policies": [{"type": "json_array_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.sse.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSON SSE streaming redaction",
                "match_path_prefix": "/json-sse-redact",
                "policies": [{"type": "json_sse_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.json.nested.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo nested JSON streaming redaction",
                "match_path_prefix": "/json-nested-redact",
                "policies": [{"type": "json_nested_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.form.urlencoded.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo form-urlencoded streaming redaction",
                "match_path_prefix": "/form-redact",
                "policies": [{"type": "form_urlencoded_stream_redaction", "max_body_bytes": 1048576}],
            }
        ),
        _upsert_policy_route(
            "demo.csv.redact.stream",
            {
                **credentialless_stream,
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
            "policy_sequence": policy_snapshot.raw["metadata"]["sequence"],
        },
    )
    return {
        "credential": credential,
        "routes": routes,
        "policy_hash": policy_snapshot.hash,
        "policy_sequence": policy_snapshot.raw["metadata"]["sequence"],
        "policy_path": str(POLICY_BUNDLE_PATH),
    }


UI_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,">
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
    html, body { max-width: 100%; overflow-x: hidden; }
    .skip-link {
      position: fixed;
      left: 12px;
      top: 8px;
      z-index: 20;
      transform: translateY(-160%);
      background: #111827;
      color: #fff;
      padding: 8px 12px;
      border-radius: 4px;
    }
    .skip-link:focus { transform: translateY(0); }
    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }
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
    .brand { display: flex; align-items: center; gap: 12px; }
    h1 { margin: 0; font-size: 18px; line-height: 1.2; }
    .mark { width: 30px; height: 30px; border-radius: 7px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); }
    .status { display: flex; gap: 12px; align-items: center; color: var(--muted); }
    .token-field { width: 220px; }
    main { display: grid; grid-template-columns: 360px minmax(0, 1fr); width: 100%; min-width: 0; min-height: calc(100vh - 64px); }
    aside { grid-column: 1; grid-row: 1 / span 7; min-width: 0; border-right: 1px solid var(--line); background: #fbfcfa; padding: 18px; }
    section { min-width: 0; padding: 18px 24px; border-bottom: 1px solid var(--line); }
    h2 { margin: 0 0 12px; font-size: 15px; }
    label { display: block; margin: 10px 0 4px; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
    input, select, textarea {
      width: 100%;
      min-width: 0;
      max-width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px 10px;
      background: #fff;
      color: var(--text);
      font: inherit;
    }
    textarea { min-height: 84px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .row { display: flex; gap: 8px; align-items: center; }
    .row > * { min-width: 0; flex: 1; }
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
    button[aria-disabled="true"] { opacity: .55; cursor: not-allowed; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); }
    th, td { border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }
    th { font-size: 12px; color: var(--muted); text-transform: uppercase; background: #fbfcfa; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .pill { display: inline-flex; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 800; }
    .pill.good { background: #dcfce7; color: var(--good); }
    .pill.warn { background: #fef3c7; color: var(--warn); }
    .pill.bad { background: #fee2e2; color: var(--bad); }
    .muted { color: var(--muted); }
    .stack { display: grid; min-width: 0; gap: 12px; }
    .toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .main-grid { display: contents; }
    .main-grid > section { grid-column: 2; overflow-x: auto; }
    .json { max-width: 420px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .hint { margin: 6px 0 0; color: var(--muted); font-size: 12px; line-height: 1.35; overflow-wrap: anywhere; }
    .output { min-height: 190px; }
    .operator-status {
      position: sticky;
      top: 64px;
      z-index: 1;
      min-height: 0;
      padding: 0 24px;
      border-bottom: 0 solid transparent;
      background: #fff;
      color: var(--text);
    }
    .operator-status:not(:empty) { padding-block: 10px; border-bottom-width: 1px; border-bottom-color: var(--line); }
    .operator-status.error { color: var(--bad); background: #fff7f7; }
    .operator-status.success { color: var(--good); background: #f3fff5; }
    .operator-status.pending { color: var(--warn); background: #fffbeb; }
    .pending-mutation { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .pending-mutation:empty { display: none; }
    .section-kicker { margin: -5px 0 10px; color: var(--muted); font-size: 12px; }
    .policy-result { min-height: 220px; }
    aside section { overflow: hidden; }
    .approval-review { border-top: 1px solid var(--line); margin-top: 12px; padding-top: 12px; }
    .review-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
    .review-field { display: grid; gap: 4px; min-width: 0; }
    .review-field span { color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; }
    .review-field code { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }
    .review-block { margin-top: 12px; display: grid; gap: 6px; }
    .review-block h3 { margin: 0; font-size: 13px; color: var(--muted); text-transform: uppercase; }
    .review-actions input { width: 72px; flex: 0 0 72px; }
    .approval-block-reason { flex-basis: 100%; color: var(--bad); font-size: 12px; line-height: 1.35; }
    .selected-row > td { background: #f0fdfa; }
    .filter-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; margin-bottom: 12px; }
    .filter-grid label { margin-top: 0; }
    .audit-summary { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 10px 0; }
    dialog { border: 1px solid var(--line); border-radius: 8px; padding: 0; width: min(420px, calc(100vw - 32px)); color: var(--ink); background: var(--surface); }
    dialog::backdrop { background: rgba(15, 23, 42, .48); }
    dialog form { display: grid; gap: 12px; padding: 20px; }
    dialog h2 { margin: 0; font-size: 18px; }
    .dialog-actions { display: flex; justify-content: flex-end; gap: 8px; }
    @media (max-width: 980px) {
      main { grid-template-columns: minmax(0, 1fr); }
      .main-grid > section { grid-column: 1; }
      aside { grid-column: 1; grid-row: auto; border-right: 0; border-bottom: 1px solid var(--line); }
      header { padding: 0 14px; }
      section { padding: 16px 14px; overflow-x: auto; }
    }
    @media (max-width: 620px) {
      header {
        display: grid;
        grid-template-columns: 1fr;
        align-items: stretch;
        gap: 10px;
        padding: 10px 14px;
      }
      .status {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
        align-items: stretch;
      }
      .status .token-field {
        grid-column: 1 / -1;
        width: 100%;
      }
      .status button,
      .status .pill {
        width: 100%;
      }
      .brand { min-height: 30px; }
      .approval-table,
      .approval-table tbody,
      .approval-table tr,
      .approval-table td { display: block; width: 100%; }
      .approval-table thead { display: none; }
      .approval-table tr {
        border: 1px solid var(--line);
        border-radius: 6px;
        margin-bottom: 10px;
        overflow: hidden;
        background: var(--panel);
      }
      .approval-table td {
        display: grid;
        grid-template-columns: minmax(72px, .3fr) minmax(0, 1fr);
        gap: 10px;
        border-bottom: 1px solid var(--line);
      }
      .approval-table td:last-child { border-bottom: 0; }
      .approval-table td::before {
        content: attr(data-label);
        color: var(--muted);
        font-size: 11px;
        font-weight: 800;
        text-transform: uppercase;
      }
      .approval-table .empty-row {
        display: block;
        border: 0;
        margin: 0;
      }
      .approval-table .empty-row td { display: block; }
      .approval-table .empty-row td::before { content: none; }
      .approval-table .review-actions { align-items: stretch; }
      .approval-table .review-actions input { width: 100%; flex-basis: 100%; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <header>
    <div class="brand"><div class="mark" aria-hidden="true"></div><h1>Serverware operator portal</h1></div>
    <div class="status">
      <span id="ca-status" class="pill warn" aria-label="Certificate authority status">CA pending</span>
      <label class="sr-only" for="admin-token">Operator admin token or OIDC JWT</label>
      <input id="admin-token" class="token-field" type="password" placeholder="Admin token or OIDC JWT" autocomplete="off">
      <button class="secondary" type="button" onclick="runUiAction('Refresh', refresh)">Refresh</button>
      <button class="secondary" type="button" onclick="runUiAction('Register passkey', registerPasskey)">Register passkey</button>
      <button type="button" onclick="runUiAction('Seed demo', seedDemo)">Seed demo</button>
    </div>
  </header>
  <div id="operator-status" class="operator-status" role="status" aria-live="polite" aria-atomic="true"></div>
  <div id="pending-mutation" class="operator-status pending pending-mutation" aria-live="polite"></div>
  <dialog id="webauthn-bootstrap-dialog">
    <form method="dialog" id="webauthn-bootstrap-form">
      <h2>Authorize first passkey</h2>
      <label for="webauthn-bootstrap-token">Bootstrap token</label>
      <input id="webauthn-bootstrap-token" type="password" autocomplete="one-time-code" required>
      <div class="dialog-actions">
        <button class="secondary" type="button" id="webauthn-bootstrap-cancel">Cancel</button>
        <button type="submit">Continue</button>
      </div>
    </form>
  </dialog>
  <main id="main-content" tabindex="-1">
    <div class="main-grid">
      <section class="jit-approvals-section">
        <h2>Approvals</h2>
        <div class="filter-grid">
          <div><label for="jit-approval-status-filter">Status</label><select id="jit-approval-status-filter"><option value="pending">Pending</option><option value="all">All</option><option value="approved">Approved</option><option value="denied">Denied</option><option value="expired">Expired</option></select></div>
          <div><label for="jit-approval-search">Search</label><input id="jit-approval-search" type="search" placeholder="Route, method, URL, principal"></div>
        </div>
        <table class="approval-table">
          <thead><tr><th>Status</th><th>Route</th><th>Request</th><th>Until</th><th></th></tr></thead>
          <tbody id="approvals"></tbody>
        </table>
        <div id="approval-review" class="approval-review" tabindex="-1" aria-label="Selected approval review"></div>
      </section>
      <section class="control-plane-approvals-section">
        <h2>Control-plane approval queue</h2>
        <p class="section-kicker">A different authorized operator must decide pending mutations</p>
        <div class="filter-grid">
          <div><label for="control-plane-status-filter">Status</label><select id="control-plane-status-filter"><option value="pending">Pending</option><option value="all">All</option><option value="approved">Approved</option><option value="denied">Denied</option><option value="expired">Expired</option></select></div>
          <div><label for="control-plane-search">Search</label><input id="control-plane-search" type="search" placeholder="Action, requester, resource"></div>
        </div>
        <table class="approval-table">
          <thead><tr><th>Status</th><th>Mutation</th><th>Requester</th><th>Expires</th><th>Decision</th></tr></thead>
          <tbody id="control-plane-approvals"></tbody>
        </table>
      </section>
    <aside>
      <div class="stack">
        <section>
          <h2>Credential</h2>
          <form id="credential-form">
            <label for="credential-name">Name</label>
            <input id="credential-name" name="name" required placeholder="Gmail OAuth token">
            <label for="credential-kind">Kind</label>
            <select id="credential-kind" name="kind">
              <option value="bearer">Bearer</option>
              <option value="header">Header</option>
              <option value="basic">Basic</option>
              <option value="query">Query</option>
              <option value="cookie">Cookie</option>
            </select>
            <label for="credential-secret">Secret</label>
            <textarea id="credential-secret" name="secret" required autocomplete="off"></textarea>
            <div id="credential-injection-name-row" hidden>
              <label id="credential-injection-name-label" for="credential-injection-name">Injection name</label>
              <input id="credential-injection-name" name="injectionName" maxlength="256" autocomplete="off">
            </div>
            <label for="credential-metadata">Metadata JSON</label>
            <textarea id="credential-metadata" name="metadata">{}</textarea>
            <button type="submit">Create credential</button>
          </form>
        </section>
        <section>
          <h2>Connect Provider Credential</h2>
          <form id="oauth-form">
            <label for="oauth-provider">Provider</label>
            <select name="provider" id="oauth-provider"></select>
            <label for="oauth-credential-name">Credential name</label>
            <input id="oauth-credential-name" name="credentialName" placeholder="Gmail OAuth - Andrew">
            <label for="oauth-scopes">Scopes</label>
            <textarea name="scopes" id="oauth-scopes"></textarea>
            <label for="oauth-metadata">Metadata JSON</label>
            <textarea id="oauth-metadata" name="metadata">{}</textarea>
            <p class="hint" id="oauth-status" role="status" aria-live="polite"></p>
            <button id="oauth-submit" type="submit">Connect with OAuth</button>
          </form>
        </section>
        <section>
          <h2>Agent Enrollment</h2>
          <form id="agent-enrollment-form">
            <label for="enrollment-principal">Principal</label>
            <select name="principalId" id="enrollment-principal"></select>
            <label for="enrollment-proxy-url">Proxy URL</label>
            <input id="enrollment-proxy-url" name="proxyUrl" value="http://localhost:8080">
            <label for="enrollment-control-plane-url">Control plane URL</label>
            <input id="enrollment-control-plane-url" name="controlPlaneUrl" value="http://localhost:3000">
            <label for="enrollment-egress-cidrs">Proxy egress CIDRs</label>
            <textarea id="enrollment-egress-cidrs" name="proxyEgressCidrs">127.0.0.1/32</textarea>
            <label for="enrollment-namespace">Namespace</label>
            <input id="enrollment-namespace" name="namespace" value="serverware-agents">
            <label for="enrollment-ca-path">CA path</label>
            <input id="enrollment-ca-path" name="caMountPath" value="/etc/serverware/serverware-ca.pem">
            <label for="enrollment-pod-selector">Pod selector JSON</label>
            <textarea id="enrollment-pod-selector" name="podSelector">{}</textarea>
            <button type="submit">Generate enrollment</button>
          </form>
          <label for="enrollment-output">Packet JSON</label>
          <textarea id="enrollment-output" class="output" readonly></textarea>
          <div class="toolbar" style="margin-top:8px">
            <button class="secondary" type="button" onclick="runUiAction('Copy enrollment', copyEnrollment)">Copy</button>
            <button class="secondary" type="button" onclick="downloadEnrollment()">Download</button>
          </div>
        </section>
        <section>
          <h2>PolicyBundle route assignment</h2>
          <p class="section-kicker">Production signed policy candidate</p>
          <form id="policy-route-form">
            <label for="policy-template">Restriction template</label>
            <select id="policy-template" name="template"></select>
            <label id="policy-custom-route-label" for="policy-custom-route" hidden>Route policy JSON</label>
            <textarea id="policy-custom-route" name="customRoute" class="policy-result" spellcheck="false" hidden></textarea>
            <label for="policy-route-id">Route ID</label>
            <input id="policy-route-id" name="routeId" required placeholder="gmail.recent.agent-a">
            <label for="policy-principal">Principal</label>
            <select id="policy-principal" name="principalId"></select>
            <label for="policy-credential">Credential reference</label>
            <select id="policy-credential" name="credentialRef"></select>
            <div id="policy-approvers-row" hidden>
              <label for="policy-approvers">Approver principal IDs</label>
              <textarea id="policy-approvers" name="approvers" placeholder="user:release-manager"></textarea>
            </div>
            <div class="toolbar" style="margin-top:10px">
              <button type="submit" class="secondary">Preview candidate</button>
              <button id="policy-stage-button" type="button" onclick="runUiAction('Stage policy candidate', stagePolicyCanary)" disabled>Stage candidate</button>
            </div>
          </form>
          <p id="policy-candidate-summary" class="hint" role="status" aria-live="polite"></p>
          <label for="policy-candidate-output">Signed candidate, diff, and dry-run</label>
          <textarea id="policy-candidate-output" class="policy-result" readonly></textarea>
          <label for="policy-canary-status">Staged candidate lifecycle</label>
          <textarea id="policy-canary-status" class="output" readonly></textarea>
          <label for="policy-canary-note">Cancellation note</label>
          <input id="policy-canary-note" maxlength="500" placeholder="Reason for cancellation">
          <div class="toolbar" style="margin-top:10px">
            <button class="secondary" type="button" onclick="runUiAction('Refresh staged candidate', refresh)">Refresh status</button>
            <button id="policy-activate-button" type="button" onclick="runUiAction('Activate staged candidate', activatePolicyCanary)" disabled>Activate</button>
              <button id="policy-cancel-button" class="danger" type="button" onclick="runUiAction('Cancel staged candidate', cancelPolicyCanary)" disabled>Cancel</button>
          </div>
        </section>
        <section>
          <h2>Local prototype route</h2>
          <p class="section-kicker">Local-only CRUD; not part of the signed production PolicyBundle</p>
          <form id="route-form">
            <label for="route-name">Name</label>
            <input id="route-name" name="name" required placeholder="Gmail recent mailbox">
            <div class="row">
              <div><label for="route-host">Host</label><input id="route-host" name="match_host" required placeholder="gmail.googleapis.com"></div>
              <div><label for="route-path">Path prefix</label><input id="route-path" name="match_path_prefix" value="/"></div>
            </div>
            <label for="route-credential">Credential</label>
            <select name="credential_id" id="route-credential"></select>
            <div class="row">
              <div><label for="route-injection-type">Injection</label><select id="route-injection-type" name="injection_type">
                <option value="bearer">Bearer</option>
                <option value="header">Header</option>
                <option value="basic">Basic</option>
                <option value="query">Query</option>
                <option value="cookie">Cookie</option>
              </select></div>
              <div><label for="route-enabled">Enabled</label><select id="route-enabled" name="enabled"><option value="true">Enabled</option><option value="false">Paused</option></select></div>
            </div>
            <label for="route-injection">Injection JSON</label>
            <textarea id="route-injection" name="injection">{"type":"bearer"}</textarea>
            <label for="route-policies">Policies JSON</label>
            <textarea id="route-policies" name="policies">[{"type":"gmail_recent","days":30},{"type":"approval","ttl_seconds":30}]</textarea>
            <div class="row">
              <div><label for="route-template">Template</label><select id="route-template"></select></div>
              <div><button type="button" class="secondary" onclick="applyRouteTemplate()">Apply template</button></div>
            </div>
            <button type="submit">Create local route</button>
          </form>
        </section>
      </div>
    </aside>
      <section class="credentials-section">
        <div class="toolbar">
          <h2 style="margin-right:auto">Credentials</h2>
          <button class="secondary" type="button" onclick="runUiAction('Copy verifier command', copyEnrollmentVerifier)">Copy verifier command</button>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Account / status</th><th>Metadata</th><th></th></tr></thead>
          <tbody id="credentials"></tbody>
        </table>
      </section>
      <section class="routes-section">
        <h2>Local prototype routes</h2>
        <table>
          <thead><tr><th>Name</th><th>Match</th><th>Credential</th><th>Injection</th><th>Policies</th><th></th></tr></thead>
          <tbody id="routes"></tbody>
        </table>
      </section>
      <section class="audit-investigation-section">
        <div class="toolbar">
          <h2 style="margin-right:auto">Audit investigation</h2>
          <button class="secondary" type="button" onclick="runUiAction('Verify audit chain', verifyAuditChain)">Verify chain</button>
          <button class="secondary" type="button" onclick="runUiAction('Export audit events', downloadAuditExport)">Export JSONL</button>
        </div>
        <form id="audit-search-form">
          <div class="filter-grid">
            <div><label for="audit-event-type">Event type</label><input id="audit-event-type" name="eventType" placeholder="credential.rotated"></div>
            <div><label for="audit-principal-id">Principal</label><input id="audit-principal-id" name="principalId" placeholder="agent:mail-reader"></div>
            <div><label for="audit-route-id">Route</label><input id="audit-route-id" name="routeId" placeholder="gmail.recent.read"></div>
            <div><label for="audit-decision">Decision</label><input id="audit-decision" name="decision" placeholder="denied"></div>
            <div><label for="audit-start">From</label><input id="audit-start" name="start" type="datetime-local"></div>
            <div><label for="audit-end">To</label><input id="audit-end" name="end" type="datetime-local"></div>
            <div><label for="audit-query">Search all fields</label><input id="audit-query" name="q" type="search" placeholder="Approval, credential, measurement"></div>
          </div>
          <button type="submit">Search audit</button>
        </form>
        <div id="audit-summary" class="audit-summary" role="status" aria-live="polite"><span class="muted">Run a search to inspect audit events.</span></div>
        <table>
          <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Evidence</th><th>Chain</th></tr></thead>
          <tbody id="audit-events"></tbody>
        </table>
      </section>
      <section class="traffic-section">
        <div class="toolbar">
          <h2 style="margin-right:auto">Traffic</h2>
          <button class="secondary" type="button" onclick="runUiAction('Clear traffic log', clearLogs)">Clear</button>
        </div>
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Route</th><th>Request</th><th>Reason</th></tr></thead>
          <tbody id="logs"></tbody>
        </table>
      </section>
    </div>
  </main>
  <script>
    let state = {credentials: [], routes: [], approvals: [], controlPlaneApprovals: [], logs: [], ca_ready: false, oauthProviders: [], policyPrincipals: [], enrollmentPacket: null, approvalReview: null, activePolicy: null, policyCandidate: null, policyCanary: null, auditSearchResult: null, auditChain: null};
    let pendingMutation = null;
    let refreshInFlight = null;
    let hasRendered = false;
    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const json = (value) => esc(JSON.stringify(value, null, 2));
    const canonicalValue = (value) => Array.isArray(value) ? value.map(canonicalValue) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])])) : value;
    const tokenKey = 'serverware.adminToken';
    const oauthDraftKey = 'serverware.oauthDraft';
    const pendingMutationKey = 'serverware.pendingMutation';
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
      },
      stripe_payment_intent_jit: {
        label: 'Stripe payment with approval',
        name: 'Stripe bounded PaymentIntent',
        host: 'api.stripe.com',
        path: '/v1/payment_intents',
        injection: {"type":"bearer"},
        policies: [
          {"type":"rateLimit","max":5,"windowSeconds":86400,"store":"shared","key":{"scope":["principal","credential","route"]}},
          {"type":"formBody","allowedFields":["amount","currency","payment_method","confirm","metadata.agent_request_id"],"requiredFields":["amount","currency","payment_method","confirm"]},
          {"type":"approval","ttl_seconds":60,"scope":"request_digest"}
        ]
      }
    };

    const policyTemplates = {
      gmail_recent: {
        label: 'Gmail messages from last 30 days',
        routeId: 'gmail.messages.last-30-days',
        provider: 'google',
        injection: {type: 'bearer', field: 'access_token'},
        match: {scheme: 'https', host: 'gmail.googleapis.com', port: 443, methods: ['GET'], paths: ['/gmail/v1/users/{user}/messages', '/gmail/v1/users/{user}/messages/{message_id}']},
        adapter: {type: 'gmail.v1', config: {maxAgeDays: 30, maxResults: 10, forceQuery: true, allowMessageGetOnlyFromPriorSearch: true, cacheTtlSeconds: 1800, denyEquivalentEndpoints: ['threads', 'history', 'attachments', 'imap'], response: {validateInternalDate: true, validateListByMetadataFetch: true, maxBodyBytes: 1048576, allowedFields: ['id', 'threadId', 'labelIds', 'snippet', 'internalDate', 'payload.headers'], allowedHeaders: [], allowedMessageHeaderNames: ['From', 'Subject', 'Date'], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error.code', 'error.status', 'error.message', 'error.errors.reason', 'error.errors.domain'], allowedHeaders: ['retry-after', 'www-authenticate'], onInvalid: 'block'}, onViolation: 'block'}}},
        constraints: [
          {id: 'gmail-max-page-size', type: 'queryNumericBounds', parameters: ['maxResults'], min: 1, max: 10, integer: true},
          {id: 'gmail-response-last-30-days', type: 'responseDateWindow', phase: 'response', operations: ['gmail.messages.list'], items: ['messages'], dateFields: ['internalDate'], formats: ['epochMillis'], maxAgeDays: 30, required: true}
        ]
      },
      x_read_recent: {
        label: 'X recent search from last 7 days',
        routeId: 'x.search.last-7-days',
        provider: 'x',
        injection: {type: 'bearer', field: 'access_token'},
        match: {scheme: 'https', host: 'api.x.com', port: 443, methods: ['GET'], paths: ['/2/tweets/search/recent']},
        adapter: {type: 'x.v2', config: {mode: 'recentSearchOnly', blockWrites: true, allowedReadOperations: ['search.read'], response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['data.id', 'data.text', 'data.created_at', 'meta.result_count'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['title', 'detail', 'type', 'status', 'errors.title', 'errors.detail', 'errors.type', 'errors.value'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: [
          {id: 'x-search-last-7-days', type: 'queryDateWindow', parameters: ['start_time', 'end_time'], maxAgeDays: 7, formats: ['rfc3339', 'date'], required: false},
          {id: 'x-search-page-cap', type: 'queryNumericBounds', parameters: ['max_results'], min: 1, max: 100, integer: true},
          {id: 'x-search-response-last-7-days', type: 'responseDateWindow', phase: 'response', items: ['data'], dateFields: ['created_at'], formats: ['rfc3339', 'date'], maxAgeDays: 7, required: true}
        ]
      },
      x_one_post_daily: {
        label: 'X one text post per day',
        routeId: 'x.post.one-per-day',
        provider: 'x',
        injection: {type: 'bearer', field: 'access_token'},
        match: {scheme: 'https', host: 'api.x.com', port: 443, methods: ['POST'], paths: ['/2/tweets']},
        adapter: {type: 'x.v2', config: {mode: 'controlledWrite', blockWrites: false, response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['data.id', 'data.text'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['title', 'detail', 'type', 'status', 'errors.title', 'errors.detail', 'errors.type', 'errors.value'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: [
          {id: 'x-only-tweet-create', type: 'operationPolicy', allowedOperations: ['tweets.write']},
          {id: 'x-one-post-per-day', type: 'rateLimit', max: 1, windowSeconds: 86400, store: 'shared', key: {scope: ['principal', 'credential', 'route', 'operation']}},
          {id: 'x-plain-text-body', type: 'jsonBody', contentTypes: ['application/json'], allowedFields: ['text', 'reply_settings'], requiredFields: ['text'], deniedFields: ['media', 'poll', 'direct_message_deep_link'], fields: {text: {type: 'string', minLength: 1, maxLength: 280}, reply_settings: {type: 'string', enum: ['following', 'mentionedUsers']}}}
        ]
      },
      npm_write_mfa: {
        label: 'npm publish with YubiKey JIT',
        routeId: 'npm.publish.yubikey-jit',
        provider: 'npm',
        injection: {type: 'bearer'},
        match: {scheme: 'https', host: 'registry.npmjs.org', port: 443, methods: ['PUT', 'POST'], paths: ['/{package}', '/-/package/{package}/dist-tags/{tag}']},
        adapter: {type: 'npm.registry', config: {operations: ['publish', 'distTagWrite'], response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['package', 'published', 'tag', 'dist_tag_written'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error', 'reason', 'code'], allowedHeaders: ['retry-after', 'www-authenticate'], onInvalid: 'block'}}}},
        constraints: [{id: 'npm-only-publish-or-dist-tag', type: 'operationPolicy', allowedOperations: ['npm.publish', 'npm.distTagWrite'], deniedOperations: ['npm.tokenWrite', 'npm.metadataWrite']}],
        jit: {required: true, mode: 'perOperation', ttlSeconds: 30, maxUses: 1, consumeOn: 'forwardStart', binding: {type: 'operationDigest', fields: ['principal', 'routeId', 'credentialRef', 'credentialVersion', 'policyHash', 'method', 'authority', 'path', 'query', 'selectedHeaders', 'bodySha256', 'packageName', 'packageVersion', 'tarballIntegrity']}, approvers: {quorum: 1, users: [], authn: {webauthnRequired: true, userVerification: 'required', allowedAuthenticatorClasses: ['yubikey', 'hardware'], requireHardwareAttestation: true}}}
      },
      stripe_readonly: {
        label: 'Stripe customers read-only',
        routeId: 'stripe.customers.read-only',
        provider: 'stripe',
        injection: {type: 'bearer'},
        match: {scheme: 'https', host: 'api.stripe.com', port: 443, methods: ['GET'], paths: ['/v1/customers', '/v1/customers/{customer_id}']},
        adapter: {type: 'generic.rest', config: {request: {allowedHeaders: ['accept', 'content-type', 'user-agent'], allowedQueryKeys: ['limit', 'starting_after', 'ending_before'], bodyMode: 'none', maxBodyBytes: 0}, response: {mode: 'json', maxBodyBytes: 1048576, allowedFields: ['id', 'object', 'email', 'name', 'created', 'data.id', 'data.email', 'data.name', 'has_more'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error.type', 'error.code', 'error.message', 'error.param'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: [{id: 'stripe-page-cap', type: 'queryNumericBounds', parameters: ['limit'], min: 1, max: 25, integer: true}]
      },
      stripe_payment_intent_jit: {
        label: 'Stripe payment + YubiKey JIT',
        routeId: 'stripe.payment-intent.tokenized-jit',
        provider: 'stripe',
        injection: {type: 'bearer'},
        match: {scheme: 'https', host: 'api.stripe.com', port: 443, methods: ['POST'], paths: ['/v1/payment_intents']},
        adapter: {type: 'generic.rest', config: {request: {allowedHeaders: ['accept', 'content-type', 'idempotency-key', 'user-agent'], allowedQueryKeys: [], bodyMode: 'formUrlencoded', maxBodyBytes: 16384, operation: {name: 'stripe.payment_intents.create', formFields: ['amount', 'currency', 'payment_method', 'confirm', 'metadata.agent_request_id']}}, response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['id', 'object', 'amount', 'currency', 'status', 'payment_method', 'created'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error.type', 'error.code', 'error.message', 'error.param'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: [
          {id: 'payment-intent-five-per-day', type: 'rateLimit', max: 5, windowSeconds: 86400, store: 'shared', key: {scope: ['principal', 'credential', 'route']}},
          {id: 'payment-intent-tokenized-only', type: 'formBody', contentTypes: ['application/x-www-form-urlencoded'], allowedFields: ['amount', 'currency', 'payment_method', 'confirm', 'metadata.agent_request_id'], requiredFields: ['amount', 'currency', 'payment_method', 'confirm'], deniedFields: ['payment_method_data.card.number', 'payment_method_data.card.cvc', 'source', 'card'], fields: {amount: {type: 'integer', min: 50, max: 50000}, currency: {type: 'string', equals: 'usd'}, payment_method: {type: 'string', pattern: '^pm_[A-Za-z0-9]{8,64}$', maxLength: 67}, confirm: {type: 'string', equals: 'true'}, 'metadata.agent_request_id': {type: 'string', maxLength: 128}}}
        ],
        jit: {required: true, mode: 'perOperation', ttlSeconds: 60, maxUses: 1, consumeOn: 'forwardStart', binding: {type: 'requestDigest', fields: ['principal', 'routeId', 'credentialRef', 'credentialVersion', 'policyHash', 'method', 'authority', 'path', 'query', 'selectedHeaders', 'bodySha256']}, approvers: {quorum: 1, users: [], authn: {webauthnRequired: true, userVerification: 'required', allowedAuthenticatorClasses: ['yubikey', 'hardware'], requireHardwareAttestation: true}}}
      },
      custom_json: {
        label: 'Custom route policy JSON',
        routeId: 'custom.restricted-operation',
        custom: true,
        injection: {type: 'bearer'},
        match: {scheme: 'https', host: 'api.internal', port: 443, methods: ['GET'], paths: ['/v1/resource']},
        adapter: {type: 'generic.rest', config: {request: {allowedHeaders: ['accept', 'user-agent'], allowedQueryKeys: [], bodyMode: 'none', maxBodyBytes: 0}, response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['id'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error', 'code', 'message'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: []
      }
    };

    function adminToken() {
      return $('admin-token').value.trim();
    }

    function adminHeaders() {
      const token = adminToken();
      return token ? {'X-Serverware-Admin-Token': token, 'Authorization': `Bearer ${token}`} : {};
    }

    function requireAdminToken() {
      if (adminToken()) return true;
      $('admin-token').placeholder = 'Admin token or OIDC JWT required';
      $('admin-token').focus();
      setStatus('Enter an operator admin token or pre-issued OIDC JWT.', 'error');
      return false;
    }

    class ApiError extends Error {
      constructor(status, payload) {
        const detail = payload && Object.prototype.hasOwnProperty.call(payload, 'detail') ? payload.detail : payload;
        const message = typeof detail === 'string' ? detail : detail && detail.message ? detail.message : `Request failed with status ${status}`;
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.payload = payload;
        this.detail = detail;
      }
    }

    function setStatus(message, tone = '') {
      const target = $('operator-status');
      target.textContent = message || '';
      target.className = `operator-status${tone ? ` ${tone}` : ''}`;
      target.setAttribute('role', tone === 'error' ? 'alert' : 'status');
    }

    async function runUiAction(label, action) {
      try {
        const result = await action();
        if (!result || (!result.pending && !result.blocked && !result.cancelled)) setStatus(`${label} complete.`, 'success');
        return result;
      } catch (error) {
        setStatus(`${label} failed: ${error.message}`, 'error');
        if (label.toLowerCase().includes('oauth')) $('oauth-status').textContent = error.message;
        return null;
      }
    }

    function controlStateKey(control) {
      if (control.id) return `id:${control.id}`;
      if (control.form && control.name) return `form:${control.form.id}:${control.name}`;
      return '';
    }

    function captureControlState() {
      const values = {};
      document.querySelectorAll('input, select, textarea').forEach((control) => {
        if (control.id === 'admin-token' || control.readOnly) return;
        const key = controlStateKey(control);
        if (!key) return;
        values[key] = {value: control.value, checked: Boolean(control.checked)};
      });
      return values;
    }

    function restoreControlState(values) {
      Object.entries(values || {}).forEach(([key, saved]) => {
        const control = key.startsWith('id:') ? $(key.slice(3)) : null;
        if (!control) return;
        if (control.tagName === 'SELECT' && !Array.from(control.options).some((option) => option.value === saved.value)) return;
        control.value = saved.value;
        if ('checked' in control) control.checked = saved.checked;
      });
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

    function splitPortalList(value) {
      return String(value || '').split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
    }

    function parseOAuthScopes(value) {
      return splitPortalList(value);
    }

    function parseProxyEgressCidrs(value) {
      return splitPortalList(value);
    }

    function generateEnrollmentNonce(randomSource = crypto) {
      return bytesToB64(randomSource.getRandomValues(new Uint8Array(32)));
    }

    function parseApproverPrincipals(value) {
      const principals = splitPortalList(value);
      if (!principals.length) throw new Error('At least one JIT approver principal is required');
      if (principals.length > 32) throw new Error('At most 32 JIT approver principals may be assigned');
      if (new Set(principals).size !== principals.length) throw new Error('JIT approver principals must be unique');
      const pattern = /^(?:user|oidc):[A-Za-z0-9][A-Za-z0-9._:@+|/-]{0,239}$/;
      if (principals.some((principal) => !pattern.test(principal))) {
        throw new Error('JIT approvers must be explicit user: or oidc: principal IDs');
      }
      return principals;
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
      const text = res.status === 204 ? '' : await res.text();
      let payload = null;
      if (text) {
        try { payload = JSON.parse(text); } catch (_) { payload = {detail: text}; }
      }
      if (res.status === 401) {
        $('admin-token').value = '';
        $('admin-token').placeholder = 'Operator token rejected';
        sessionStorage.removeItem(tokenKey);
      }
      if (!res.ok) throw new ApiError(res.status, payload);
      if (res.status === 204) return null;
      return payload;
    }

    function persistPendingMutation() {
      if (pendingMutation && pendingMutation.persist) {
        sessionStorage.setItem(pendingMutationKey, JSON.stringify(pendingMutation));
      } else {
        sessionStorage.removeItem(pendingMutationKey);
      }
    }

    function restorePendingMutation() {
      try {
        pendingMutation = JSON.parse(sessionStorage.getItem(pendingMutationKey) || 'null');
      } catch (_) {
        pendingMutation = null;
        sessionStorage.removeItem(pendingMutationKey);
      }
      renderPendingMutation();
    }

    function renderPendingMutation() {
      const target = $('pending-mutation');
      if (!pendingMutation) {
        target.replaceChildren();
        return;
      }
      const summary = document.createElement('span');
      summary.textContent = `${pendingMutation.label} awaits approval ${pendingMutation.approvalId}.`;
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = 'Continue approved request';
      button.addEventListener('click', () => runUiAction('Continue mutation', continuePendingMutation));
      target.replaceChildren(summary, button);
    }

    async function controlPlaneAssertion(challengeDetail) {
      if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('WebAuthn is not available in this browser');
      const options = await api('/api/control-plane/mutations/webauthn/options', {
        method: 'POST',
        body: JSON.stringify({
          action: challengeDetail.action,
          resourceId: challengeDetail.resourceId ?? null,
          payloadDigest: challengeDetail.payloadDigest
        })
      });
      if (!(options.publicKey.allowCredentials || []).length) throw new Error('No registered passkey is available for this operator');
      const assertion = await navigator.credentials.get({publicKey: prepareRequestOptions(options)});
      return credentialToJson(assertion);
    }

    function mutationOptions(mutation) {
      return {
        method: mutation.method || 'POST',
        body: JSON.stringify(mutation.body || {})
      };
    }

    async function runControlPlaneMutation(original) {
      const mutation = JSON.parse(JSON.stringify(original));
      while (true) {
        try {
          const result = await api(mutation.path, mutationOptions(mutation));
          if (pendingMutation && (!mutation.approvalId || pendingMutation.approvalId === mutation.approvalId)) {
            pendingMutation = null;
            persistPendingMutation();
            renderPendingMutation();
          }
          return {pending: false, result, mutation};
        } catch (error) {
          const detail = error instanceof ApiError ? error.detail : null;
          if (error.status === 412 && detail && detail.error === 'control_plane_webauthn_required') {
            const assertion = await controlPlaneAssertion(detail);
            mutation.body = mutation.body || {};
            mutation.body.mfa = {...(mutation.body.mfa || {}), assertion};
            continue;
          }
          if (error.status === 428 && detail && detail.error === 'control_plane_approval_required') {
            mutation.body = mutation.body || {};
            const mfa = {...(mutation.body.mfa || {}), approvalId: detail.approvalId};
            delete mfa.assertion;
            mutation.body.mfa = mfa;
            mutation.approvalId = detail.approvalId;
            pendingMutation = mutation;
            persistPendingMutation();
            renderPendingMutation();
            setStatus(`${mutation.label} is waiting for approval ${detail.approvalId}.`, 'pending');
            await refresh();
            return {pending: true, approval: detail};
          }
          throw error;
        }
      }
    }

    async function continuePendingMutation() {
      if (!pendingMutation) throw new Error('No control-plane mutation is waiting');
      await refresh();
      const approval = (state.controlPlaneApprovals || []).find((item) => item.id === pendingMutation.approvalId);
      if (!approval) throw new Error('Pending approval is not visible to this operator');
      if (approval.status === 'pending') {
        setStatus(`Approval ${approval.id} is still pending.`, 'pending');
        return {pending: true};
      }
      if (approval.status !== 'approved') throw new Error(`Approval ${approval.id} is ${approval.status}`);
      const completed = await runControlPlaneMutation(pendingMutation);
      if (completed.pending) return completed;
      await finishMutation(completed.mutation, completed.result);
      return completed;
    }

    async function finishMutation(mutation, result) {
      if (mutation.kind === 'oauth-start') {
        sessionStorage.removeItem(oauthDraftKey);
        window.location.assign(result.authorizationUrl);
        return;
      }
      if (mutation.kind === 'policy-canary') {
        state.policyCandidate.stage = result;
        renderPolicyCandidate();
      }
      if (mutation.kind === 'webauthn-register-options') {
        await completePasskeyRegistration(result);
        return;
      }
      await refresh();
    }

    async function refresh() {
      if (refreshInFlight) return refreshInFlight;
      if (!adminToken()) {
        render();
        return;
      }
      const controlState = captureControlState();
      refreshInFlight = (async () => {
        const retained = {
          enrollmentPacket: state.enrollmentPacket,
          approvalReview: state.approvalReview,
          policyCandidate: state.policyCandidate,
          auditSearchResult: state.auditSearchResult,
          auditChain: state.auditChain
        };
        const bootstrap = await api('/api/bootstrap');
        const [controlPlaneResult, policyResult, policyCanaryResult] = await Promise.allSettled([
          api('/api/control-plane/approvals?limit=100'),
          api('/api/policy'),
          api('/api/policy/canary/status')
        ]);
        state = {
          ...bootstrap,
          controlPlaneApprovals: controlPlaneResult.status === 'fulfilled' ? controlPlaneResult.value : [],
          activePolicy: policyResult.status === 'fulfilled' ? policyResult.value : null,
          policyCanary: policyCanaryResult.status === 'fulfilled' ? policyCanaryResult.value : null,
          ...retained
        };
        state.approvalReview = retained.approvalReview && state.approvals.some((item) => item.id === retained.approvalReview.id) ? retained.approvalReview : null;
        render(controlState);
      })();
      try {
        return await refreshInFlight;
      } catch (error) {
        setStatus(`Refresh failed: ${error.message}`, 'error');
        throw error;
      } finally {
        refreshInFlight = null;
      }
    }

    function credentialName(id) {
      return (state.credentials.find((item) => item.id === id) || {}).name || 'None';
    }

    function routeName(id) {
      return (state.routes.find((item) => item.id === id) || {}).name || id || 'None';
    }

    function credentialAccountStatus(item) {
      const metadata = item.metadata || {};
      if (item.kind !== 'oauth2' || metadata.oauth !== true) return '<span class="muted">Stored credential</span>';
      const account = metadata.provider_account || metadata.account || metadata.account_email || metadata.provider_subject || metadata.subject || 'Unknown account';
      const provider = metadata.provider_id || 'oauth';
      const scopes = Array.isArray(metadata.scopes) ? metadata.scopes.join(', ') : '';
      const expires = Number(metadata.expires_at_epoch_ms || 0);
      const healthy = Number.isFinite(expires) && expires > Date.now();
      const verified = metadata.provider_identity_verified === true ? '<span class="pill good">verified identity</span>' : '<span class="pill warn">identity unverified</span>';
      const status = healthy
        ? '<span class="pill good">connected</span>'
        : metadata.refreshable === true
          ? '<span class="pill warn">refresh on use</span>'
          : '<span class="pill bad">reconnect</span>';
      const expiry = expires ? new Date(expires).toLocaleString() : 'unknown expiry';
      return `<div class="stack"><div class="toolbar">${status}${verified}</div><strong>${esc(account)}</strong><span class="muted">${esc(provider)} / ${esc(expiry)}</span>${scopes ? `<span class="muted">${esc(scopes)}</span>` : ''}</div>`;
    }

    function syncCredentialKindFields(reset = false) {
      const kind = $('credential-kind').value;
      const settings = {
        header: ['Header name', 'x-api-key'],
        basic: ['Username', 'service-account'],
        query: ['Query parameter', 'api_key'],
        cookie: ['Cookie name', 'session_token']
      };
      const selected = settings[kind] || null;
      $('credential-injection-name-row').hidden = !selected;
      $('credential-injection-name').required = Boolean(selected);
      if (selected) {
        $('credential-injection-name-label').textContent = selected[0];
        $('credential-injection-name').placeholder = selected[1];
      }
      if (reset || !selected) $('credential-injection-name').value = '';
    }

    function pill(status) {
      const cls = status === 'approved' || status === 'allowed' || status === 'response' ? 'good' : status === 'pending' || status === 'blocked' ? 'warn' : 'bad';
      return `<span class="pill ${cls}">${esc(status)}</span>`;
    }

    function policyCredentialOptions(template) {
      const items = new Map();
      const activeCredentials = state.activePolicy && state.activePolicy.bundle ? state.activePolicy.bundle.credentials || [] : [];
      activeCredentials.forEach((item) => items.set(item.id, {id: item.id, label: `${item.id} (active bundle)`, activeCredential: item, storedCredential: null}));
      (state.credentials || []).forEach((item) => {
        const current = items.get(item.id) || {id: item.id, activeCredential: null};
        const identity = item.metadata?.provider_account || item.metadata?.account || item.metadata?.account_email || item.metadata?.provider_subject || item.metadata?.subject || '';
        const provider = item.metadata?.provider_id || '';
        const identityLabel = [identity, provider].filter(Boolean).join(' / ');
        items.set(item.id, {...current, label: `${item.name}${identityLabel ? ` - ${identityLabel}` : ''} (${item.id})`, storedCredential: item});
      });
      return Array.from(items.values()).map((item) => {
        try {
          policyCredentialInjection(item.storedCredential, item.activeCredential, template);
          return {...item, compatible: true, reason: ''};
        } catch (error) {
          return {...item, compatible: false, reason: error.message};
        }
      });
    }

    function renderPolicyCredentialOptions(preferredCredential = '') {
      const template = policyTemplates[$('policy-template').value];
      const items = template ? policyCredentialOptions(template) : [];
      $('policy-credential').innerHTML = items.map((item) => `<option value="${esc(item.id)}" ${item.compatible ? '' : 'disabled'} title="${esc(item.reason)}">${esc(item.label)}${item.compatible ? '' : ' (not compatible)'}</option>`).join('');
      const preferred = items.find((item) => item.id === preferredCredential && item.compatible);
      const selected = preferred || items.find((item) => item.compatible);
      $('policy-credential').value = selected?.id || '';
      $('policy-credential').disabled = !selected;
    }

    function renderPolicyPrincipalOptions() {
      const options = (state.policyPrincipals || []).map((item) => `<option value="${esc(item.id)}">${esc(item.id)}</option>`).join('');
      $('enrollment-principal').innerHTML = (state.policyPrincipals || []).map((item) => `<option value="${esc(item.id)}">${esc(item.id)} (${esc(item.routeCount)} routes)</option>`).join('');
      $('policy-principal').innerHTML = options;
    }

    function render(controlState = captureControlState()) {
      $('ca-status').textContent = state.ca_ready ? 'CA ready' : 'CA pending';
      $('ca-status').className = state.ca_ready ? 'pill good' : 'pill warn';
      $('route-credential').innerHTML = '<option value="">None</option>' + state.credentials.map((item) => `<option value="${esc(item.id)}">${esc(item.name)}</option>`).join('');
      $('route-template').innerHTML = Object.entries(routeTemplates).map(([key, item]) => `<option value="${esc(key)}">${esc(item.label)}</option>`).join('');
      $('oauth-provider').innerHTML = (state.oauthProviders || []).map((item) => `<option value="${esc(item.id)}">${esc(item.displayName)}${item.configured ? '' : ' (not configured)'}</option>`).join('');
      $('policy-template').innerHTML = Object.entries(policyTemplates).map(([key, item]) => `<option value="${esc(key)}">${esc(item.label)}</option>`).join('');
      const preferredTemplate = controlState['id:policy-template']?.value;
      if (preferredTemplate && policyTemplates[preferredTemplate]) $('policy-template').value = preferredTemplate;
      syncPolicyTemplateEditor();
      renderPolicyPrincipalOptions();
      renderPolicyCredentialOptions(controlState['id:policy-credential']?.value || '');
      renderEnrollmentOutput();
      $('credentials').innerHTML = state.credentials.map((item) => `
        <tr>
          <td><strong>${esc(item.name)}</strong><br><code>${esc(item.id)}</code></td>
          <td>${esc(item.kind)}</td>
          <td>${credentialAccountStatus(item)}</td>
          <td><code class="json">${json(item.metadata)}</code></td>
          <td><button class="danger" type="button" onclick="runUiAction('Delete credential', () => deleteCredential('${item.id}'))">Delete</button></td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">No credentials</td></tr>';

      $('routes').innerHTML = state.routes.map((item) => `
        <tr>
          <td>${item.enabled ? pill('enabled') : pill('paused')}<br><strong>${esc(item.name)}</strong><br><code>${esc(item.id)}</code></td>
          <td><code>${esc(item.match_host)}${esc(item.match_path_prefix)}</code></td>
          <td>${esc(credentialName(item.credential_id))}</td>
          <td><code class="json">${json(item.injection)}</code></td>
          <td><code class="json">${json(item.policies)}</code></td>
          <td><button class="danger" type="button" onclick="runUiAction('Delete local route', () => deleteRoute('${item.id}'))">Delete</button></td>
        </tr>`).join('') || '<tr><td colspan="6" class="muted">No routes</td></tr>';

      renderJitApprovals();
      renderControlPlaneApprovals();
      renderPolicyCandidate();
      renderPolicyCanary();
      renderAuditInvestigation();

      $('logs').innerHTML = state.logs.map((item) => `
        <tr>
          <td><code>${esc(item.created_at)}</code></td>
          <td>${pill(item.action)}</td>
          <td>${esc(item.status_code || '')}</td>
          <td>${esc(routeName(item.route_id))}</td>
          <td><strong>${esc(item.method)}</strong><br><code>${esc(item.url)}</code></td>
          <td>${esc(item.reason || '')}</td>
        </tr>`).join('') || '<tr><td colspan="6" class="muted">No traffic</td></tr>';
      restoreControlState(controlState);
      syncCredentialKindFields();
      renderOAuthDefaults(!hasRendered);
      renderPendingMutation();
      hasRendered = true;
    }

    function renderOAuthDefaults(applyDefaults = true) {
      const provider = (state.oauthProviders || []).find((item) => item.id === $('oauth-provider').value) || (state.oauthProviders || []).find((item) => item.configured) || (state.oauthProviders || [])[0];
      if (!provider) {
        $('oauth-status').textContent = 'No OAuth providers configured.';
        $('oauth-submit').disabled = true;
        return;
      }
      if (applyDefaults && !$('oauth-scopes').value.trim()) $('oauth-scopes').value = (provider.defaultScopes || []).join('\n');
      $('oauth-submit').disabled = !provider.configured;
      $('oauth-status').textContent = provider.configured ? `Redirect URI: ${provider.redirectUri}` : `Set OAuth client env vars for ${provider.displayName}.`;
    }

    function safeControlPlaneRequest(request) {
      const allowed = [
        'credential_type', 'provider', 'credential_name', 'scopes', 'metadata_keys', 'name', 'kind',
        'policy_id', 'previous_policy_hash', 'candidate_policy_hash', 'previous_sequence', 'new_sequence',
        'previous_rollback_epoch', 'new_rollback_epoch', 'diff', 'dry_run', 'route_id', 'changed_fields',
        'match_host', 'match_path_prefix', 'credential_id', 'enabled', 'subject_id', 'roles', 'reason'
      ];
      return Object.fromEntries(allowed.filter((key) => Object.prototype.hasOwnProperty.call(request || {}, key)).map((key) => [key, request[key]]));
    }

    function renderControlPlaneApprovals() {
      const status = $('control-plane-status-filter').value;
      const query = $('control-plane-search').value.trim().toLowerCase();
      const rows = (state.controlPlaneApprovals || [])
        .filter((item) => status === 'all' || item.status === status)
        .filter((item) => !query || [item.action, item.requester_id, item.resource_id, item.payload_digest].some((value) => String(value || '').toLowerCase().includes(query)))
        .sort((left, right) => queueStatusRank(left.status) - queueStatusRank(right.status) || String(right.created_at || '').localeCompare(String(left.created_at || '')));
      $('control-plane-approvals').innerHTML = rows.map((item) => {
        const decisionId = `control-plane-note-${item.id}`;
        const resource = item.resource_id ? `<br><code>${esc(item.resource_id)}</code>` : '';
        const summary = safeControlPlaneRequest(item.request);
        const actions = item.status === 'pending' ? `
          <label class="sr-only" for="${decisionId}">Approval decision note</label>
          <input id="${decisionId}" placeholder="Decision note" maxlength="500">
          <div class="toolbar" style="margin-top:6px">
            <button type="button" onclick="runUiAction('Approve control-plane mutation', () => decideControlPlaneApproval('${item.id}', 'approve'))">Approve</button>
            <button class="danger" type="button" onclick="runUiAction('Deny control-plane mutation', () => decideControlPlaneApproval('${item.id}', 'deny'))">Deny</button>
          </div>` : `<span class="muted">${esc(item.decision_note || 'Decided')}</span>`;
        return `<tr>
          <td data-label="Status">${pill(item.status)}</td>
          <td data-label="Mutation"><strong>${esc(item.action)}</strong>${resource}<br><code>${esc(item.payload_digest)}</code><br><code class="json">${json(summary)}</code></td>
          <td data-label="Requester"><code>${esc(item.requester_id)}</code></td>
          <td data-label="Expires"><code>${esc(item.expires_at)}</code></td>
          <td data-label="Decision">${actions}</td>
        </tr>`;
      }).join('') || '<tr class="empty-row"><td colspan="5" class="muted">No control-plane approvals</td></tr>';
    }

    function queueStatusRank(status) {
      return status === 'pending' ? 0 : status === 'approved' ? 1 : status === 'denied' ? 2 : 3;
    }

    function renderJitApprovals() {
      const status = $('jit-approval-status-filter').value;
      const query = $('jit-approval-search').value.trim().toLowerCase();
      const rows = (state.approvals || [])
        .filter((item) => status === 'all' || item.status === status)
        .filter((item) => !query || [item.id, item.route_id, item.principal_id, item.method, item.url].some((value) => String(value || '').toLowerCase().includes(query)))
        .sort((left, right) => queueStatusRank(left.status) - queueStatusRank(right.status) || String(right.requested_at || '').localeCompare(String(left.requested_at || '')));
      $('approvals').innerHTML = rows.map((item) => {
        const approvalBlockReason = approvalReviewBlockReason(item);
        const approvalBlockReasonId = `jit-approval-block-reason-${item.id}`;
        const approvalBlockAttributes = approvalBlockReason ? `aria-disabled="true" aria-describedby="${approvalBlockReasonId}"` : '';
        const approvalBlockMessage = approvalBlockReason ? `<span id="${approvalBlockReasonId}" class="approval-block-reason" role="status">${esc(approvalBlockReason)}</span>` : '';
        const grantTtlSeconds = Number(item.grant_ttl_seconds || 30);
        const selected = state.approvalReview?.id === item.id ? ' class="selected-row" aria-current="true"' : '';
        return `<tr${selected}>
          <td data-label="Status">${pill(item.status)}</td>
          <td data-label="Route">${esc(routeName(item.route_id))}</td>
          <td data-label="Request"><strong>${esc(item.method)}</strong><br><code>${esc(item.url)}</code></td>
          <td data-label="Until"><code>${esc(item.approved_until || item.expires_at)}</code></td>
          <td data-label="Actions"><div class="toolbar review-actions"><button class="secondary" type="button" onclick="runUiAction('Load approval review', () => loadApprovalReview('${item.id}'))">Review</button>${item.status === 'pending' ? `<span class="muted">${esc(grantTtlSeconds)}s policy grant</span><button type="button" onclick="runUiAction('Approve request', () => approve('${item.id}'))" ${approvalBlockAttributes}>Approve</button>${approvalBlockMessage}<label class="sr-only" for="jit-deny-note-${item.id}">Denial reason</label><input id="jit-deny-note-${item.id}" placeholder="Denial reason"><button class="danger" type="button" onclick="runUiAction('Deny request', () => deny('${item.id}'))">Deny</button>` : ''}</div></td>
        </tr>`;
      }).join('') || '<tr class="empty-row"><td colspan="5" class="muted">No matching approvals</td></tr>';
      renderApprovalReview();
    }

    function redactAuditEvidence(value, key = '') {
      if (/(secret|token|authorization|password|cookie|assertion|client.?data|credential.?material|private.?key)/i.test(key)) return '[redacted]';
      if (Array.isArray(value)) return value.map((item) => redactAuditEvidence(item));
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([itemKey, item]) => [itemKey, redactAuditEvidence(item, itemKey)]));
      return value;
    }

    function renderAuditInvestigation() {
      const result = state.auditSearchResult;
      const chain = state.auditChain;
      const chainPill = chain ? pill(chain.ok === true && chain.complete !== false ? 'approved' : 'denied') : '<span class="pill warn">not verified</span>';
      $('audit-summary').innerHTML = result
        ? `${result.complete ? '<span class="pill good">complete scan</span>' : '<span class="pill warn">partial scan</span>'}<strong>${esc(result.count)} shown</strong><span class="muted">${esc(result.matched_in_scan)} matched / ${esc(result.scanned)} scanned / ${esc(result.total_candidates)} candidates</span>${chainPill}`
        : `<span class="muted">Run a search to inspect audit events.</span>${chain ? chainPill : ''}`;
      const items = result?.items || [];
      $('audit-events').innerHTML = items.map((item) => `
        <tr>
          <td><code>${esc(item.created_at)}</code></td>
          <td><strong>${esc(item.event_type)}</strong><br><code>${esc(item.id)}</code></td>
          <td><code>${esc(item.actor_type || '')}:${esc(item.actor_id || '')}</code></td>
          <td><code class="json">${json(redactAuditEvidence(item.event || {}))}</code></td>
          <td><code title="${esc(item.event_hash || '')}">${esc(String(item.event_hash || '').slice(0, 18))}${item.event_hash ? '...' : ''}</code></td>
        </tr>`).join('') || '<tr><td colspan="5" class="muted">No matching audit events</td></tr>';
    }

    async function decideControlPlaneApproval(id, decision) {
      const note = $(`control-plane-note-${id}`)?.value.trim() || null;
      await api(`/api/control-plane/approvals/${id}/${decision}`, {
        method: 'POST',
        body: JSON.stringify({note})
      });
      await refresh();
    }

    function materializePolicyPath(path) {
      const concrete = path.replace(/\{[^}]+\}/g, 'example');
      return concrete.endsWith('/**') ? `${concrete.slice(0, -3)}/example` : concrete;
    }

    function injectionField(metadata) {
      const field = metadata?.injection_field;
      if (field == null || field === '') return null;
      if (typeof field !== 'string' || field.length > 256 || !/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(field)) {
        throw new Error('Credential injection_field must be a dotted JSON object path');
      }
      return field;
    }

    function injectionPrefix(metadata) {
      const prefix = metadata?.injection_prefix;
      if (prefix == null) return null;
      if (typeof prefix !== 'string' || prefix.length > 128 || /[\r\n]/.test(prefix)) {
        throw new Error('Credential injection_prefix must be a single line of at most 128 characters');
      }
      return prefix;
    }

    function injectionName(credential, label, {header = false} = {}) {
      const name = credential?.metadata?.injection_name;
      const tokenPattern = /^[!#$%&'*+.^_`|~A-Za-z0-9-]+$/;
      if (typeof name !== 'string' || !name || name.length > 128 || !tokenPattern.test(name)) {
        throw new Error(`Credential ${credential?.id || 'unknown'} requires a valid ${label} in metadata.injection_name`);
      }
      if (header) {
        const lowered = name.toLowerCase();
        const forbidden = new Set(['authorization', 'proxy-authorization', 'cookie', 'host', 'content-length', 'connection', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
        if (forbidden.has(lowered) || lowered.startsWith('x-serverware-')) {
          throw new Error(`Credential ${credential.id} uses a forbidden injection header`);
        }
      }
      return name;
    }

    function basicUsername(credential) {
      const username = credential?.metadata?.username;
      if (typeof username !== 'string' || !username || username.length > 256 || /[\s:\u0000-\u001f\u007f]/.test(username)) {
        throw new Error(`Credential ${credential?.id || 'unknown'} requires a valid Basic username in metadata.username`);
      }
      return username;
    }

    function storedCredentialInjection(credential) {
      if (!credential) return null;
      const metadata = credential.metadata || {};
      const field = injectionField(metadata);
      const prefix = injectionPrefix(metadata);
      if (credential.kind === 'oauth2') {
        return {type: 'bearer', header: 'Authorization', field: field || 'access_token', ...(prefix == null ? {} : {prefix})};
      }
      if (credential.kind === 'bearer') {
        return {type: 'bearer', header: 'Authorization', ...(field ? {field} : {}), ...(prefix == null ? {} : {prefix})};
      }
      if (credential.kind === 'header') {
        return {type: 'header', name: injectionName(credential, 'header name', {header: true}), ...(field ? {field} : {}), ...(prefix == null ? {} : {prefix})};
      }
      if (credential.kind === 'query') {
        return {type: 'query', name: injectionName(credential, 'query parameter name'), ...(field ? {field} : {})};
      }
      if (credential.kind === 'cookie') {
        return {type: 'cookie', name: injectionName(credential, 'cookie name'), ...(field ? {field} : {})};
      }
      if (credential.kind === 'basic') {
        return {type: 'basic', username: basicUsername(credential), ...(field ? {field} : {})};
      }
      throw new Error(`Credential ${credential.id} has unsupported kind ${credential.kind || 'unknown'}`);
    }

    function normalizedInjectionShape(injection) {
      if (!injection || typeof injection !== 'object') return null;
      const type = String(injection.type || '');
      if (type === 'bearer') return {type, header: String(injection.header || 'Authorization').toLowerCase(), prefix: String(injection.prefix ?? 'Bearer '), field: String(injection.field || '')};
      if (type === 'header') return {type, name: String(injection.name || 'x-api-key').toLowerCase(), prefix: String(injection.prefix || ''), field: String(injection.field || '')};
      if (type === 'query') return {type, name: String(injection.name || 'access_token'), field: String(injection.field || '')};
      if (type === 'cookie') return {type, name: String(injection.name || 'serverware_token'), field: String(injection.field || '')};
      if (type === 'basic') return {type, username: String(injection.username || ''), field: String(injection.field || '')};
      return null;
    }

    function injectionShapesCompatible(actual, required) {
      const actualShape = normalizedInjectionShape(actual);
      const requiredShape = normalizedInjectionShape(required);
      return Boolean(actualShape && requiredShape && JSON.stringify(actualShape) === JSON.stringify(requiredShape));
    }

    function bearerInjectionCompatible(actual, required) {
      return actual?.type === 'bearer' && required?.type === 'bearer' && injectionShapesCompatible(actual, required);
    }

    function oauthCredentialGrantedScopes(credential) {
      if (credential?.kind !== 'oauth2') return null;
      const rawScopes = credential.metadata?.scopes;
      if (!Array.isArray(rawScopes) || rawScopes.length === 0 || rawScopes.length > 30) {
        throw new Error(`OAuth credential ${credential.id} has malformed granted-scope metadata`);
      }
      const scopes = rawScopes.map((scope) => {
        if (typeof scope !== 'string' || !scope || scope !== scope.trim() || /\s/.test(scope) || scope.length > 200) {
          throw new Error(`OAuth credential ${credential.id} has malformed granted-scope metadata`);
        }
        return scope;
      });
      if (new Set(scopes).size !== scopes.length) {
        throw new Error(`OAuth credential ${credential.id} has duplicate granted-scope metadata`);
      }
      return scopes.slice().sort();
    }

    function oauthCredentialProviderSubject(credential) {
      if (credential?.kind !== 'oauth2') return null;
      if (
        credential.metadata?.oauth !== true
        || credential.metadata?.provider_identity_verified !== true
        || typeof credential.metadata?.provider_id !== 'string'
        || !credential.metadata.provider_id.trim()
      ) {
        throw new Error(`OAuth credential ${credential.id} is not bound to a verified provider identity`);
      }
      const subject = credential.metadata?.provider_subject;
      if (
        typeof subject !== 'string'
        || !subject
        || subject !== subject.trim()
        || subject.length > 512
        || /[\u0000-\u001f\u007f]/.test(subject)
      ) {
        throw new Error(`OAuth credential ${credential.id} has malformed verified provider-subject metadata`);
      }
      return subject;
    }

    function policyCredentialInjection(credential, activeCredential, template) {
      const storedInjection = storedCredentialInjection(credential);
      const activeInjection = activeCredential?.injection || null;
      const candidateInjection = activeInjection || storedInjection;
      if (template.custom) {
        if (!candidateInjection) throw new Error(`Credential ${credential?.id || activeCredential?.id || 'unknown'} has no supported PolicyBundle injection shape`);
        if (storedInjection && activeInjection && !injectionShapesCompatible(activeInjection, storedInjection)) {
          throw new Error(`Credential ${credential.id} does not match its active PolicyBundle injection shape`);
        }
        return JSON.parse(JSON.stringify(candidateInjection));
      }
      if (!candidateInjection || !bearerInjectionCompatible(candidateInjection, template.injection)) {
        throw new Error(`Credential ${credential?.id || activeCredential?.id || 'unknown'} uses an injection shape that is incompatible with this template`);
      }
      if (storedInjection && activeInjection && !injectionShapesCompatible(activeInjection, storedInjection)) {
        throw new Error(`Credential ${credential.id} does not match its active PolicyBundle injection shape`);
      }
      if (credential?.kind === 'oauth2') {
        const providerId = String(credential.metadata?.provider_id || '');
        if (!providerId || providerId !== template.provider) {
          throw new Error(`OAuth credential ${credential.id} belongs to ${providerId || 'an unknown provider'}, not ${template.provider}`);
        }
      }
      if (template.adapter?.type === 'x.v2') {
        const appId = String(credential?.metadata?.x_app_id || credential?.metadata?.app_id || '');
        if (!appId) throw new Error(`X credential ${credential?.id || 'unknown'} is missing its OAuth app ID binding`);
      }
      return JSON.parse(JSON.stringify(candidateInjection));
    }

    function syncPolicyTemplateEditor(reset = false) {
      const template = policyTemplates[$('policy-template').value];
      const custom = Boolean(template?.custom);
      const needsApprovers = Boolean(template?.jit && !custom);
      $('policy-custom-route-label').hidden = !custom;
      $('policy-custom-route').hidden = !custom;
      $('policy-approvers-row').hidden = !needsApprovers;
      $('policy-approvers').required = needsApprovers;
      if (reset) $('policy-approvers').value = '';
      if (custom && (reset || !$('policy-custom-route').value.trim())) {
        $('policy-custom-route').value = JSON.stringify({
          match: template.match,
          adapter: template.adapter,
          constraints: template.constraints || [],
          ...(template.jit ? {jit: template.jit} : {})
        }, null, 2);
      }
    }

    function buildPolicyCandidate() {
      if (!state.activePolicy || !state.activePolicy.ready || !state.activePolicy.bundle) throw new Error('Active signed PolicyBundle is unavailable');
      const form = new FormData($('policy-route-form'));
      const template = policyTemplates[form.get('template')];
      if (!template) throw new Error('Select a policy route template');
      const routeId = String(form.get('routeId') || '').trim();
      const principalId = String(form.get('principalId') || '').trim();
      const credentialRef = String(form.get('credentialRef') || '').trim();
      if (!routeId || !principalId || !credentialRef) throw new Error('Route ID, principal, and credential reference are required');
      const bundle = JSON.parse(JSON.stringify(state.activePolicy.bundle));
      bundle.metadata = {...(bundle.metadata || {}), sequence: Number(bundle.metadata?.sequence || 0) + 1};
      delete bundle.metadata.signature;
      delete bundle.metadata.signingKeyId;
      bundle.credentials = bundle.credentials || [];
      const activeCredential = bundle.credentials.find((item) => item.id === credentialRef);
      const storedCredential = (state.credentials || []).find((item) => item.id === credentialRef);
      const candidateInjection = policyCredentialInjection(storedCredential, activeCredential, template);
      const grantedScopes = oauthCredentialGrantedScopes(storedCredential);
      const providerSubject = oauthCredentialProviderSubject(storedCredential);
      if (!activeCredential) {
        const provider = template.provider || storedCredential?.metadata?.provider_id || storedCredential?.metadata?.provider || 'custom';
        bundle.credentials.push({
          id: credentialRef,
          provider,
          ...(grantedScopes ? {scopes: grantedScopes} : {}),
          ...(providerSubject ? {providerSubject} : {}),
          injection: candidateInjection
        });
      } else {
        if (grantedScopes) activeCredential.scopes = grantedScopes;
        if (providerSubject) activeCredential.providerSubject = providerSubject;
      }
      let route;
      if (template.custom) {
        const parsed = JSON.parse(String(form.get('customRoute') || '{}'));
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('Custom route policy must be a JSON object');
        route = JSON.parse(JSON.stringify(parsed));
        route.id = routeId;
        route.principals = [principalId];
        route.credentialRef = credentialRef;
        if (!route.match || !route.adapter) throw new Error('Custom route policy requires match and adapter objects');
        if (!Array.isArray(route.constraints)) route.constraints = [];
      } else {
        route = {
          id: routeId,
          principals: [principalId],
          match: JSON.parse(JSON.stringify(template.match)),
          credentialRef,
          adapter: JSON.parse(JSON.stringify(template.adapter)),
          constraints: JSON.parse(JSON.stringify(template.constraints || []))
        };
        if (route.adapter.type === 'x.v2') {
          route.adapter.config.appIds = [String(storedCredential.metadata.x_app_id || storedCredential.metadata.app_id)];
        }
        if (template.jit) {
          route.jit = JSON.parse(JSON.stringify(template.jit));
          route.jit.approvers.users = parseApproverPrincipals(form.get('approvers'));
        }
      }
      const existingIndex = (bundle.routes || []).findIndex((item) => item.id === routeId);
      if (existingIndex >= 0) bundle.routes[existingIndex] = route;
      else (bundle.routes = bundle.routes || []).push(route);
      const allowPath = materializePolicyPath(route.match.paths[0]);
      const dryRun = [
        {name: `${routeId} allows assigned operation`, principalId, scheme: 'https', host: route.match.host, port: route.match.port, method: route.match.methods[0], path: allowPath, expect: 'allow'},
        {name: `${routeId} keeps unknown host denied`, principalId, scheme: 'https', host: 'serverware-policy-deny.invalid', port: 443, method: route.match.methods[0], path: allowPath, expect: 'deny'}
      ];
      return {bundle, dryRun, basePolicyHash: state.activePolicy.policy_hash, routeId};
    }

    async function previewPolicyCandidate() {
      const candidate = buildPolicyCandidate();
      const report = await api('/api/policy/candidate', {
        method: 'POST',
        body: JSON.stringify({bundle: candidate.bundle, dryRun: candidate.dryRun})
      });
      state.policyCandidate = {...candidate, report, stage: null};
      renderPolicyCandidate();
      return report;
    }

    function renderPolicyCandidate() {
      const candidate = state.policyCandidate;
      const report = candidate?.report;
      const checks = Array.isArray(report?.dryRun?.results) ? report.dryRun.results : [];
      const dryRunPassed = report?.dryRun?.passed === true && checks.length > 0 && checks.every((item) => item.passed === true);
      $('policy-stage-button').disabled = !candidate || !report || !state.activePolicy || !dryRunPassed;
      $('policy-candidate-output').value = candidate ? JSON.stringify({candidate: candidate.report, stage: candidate.stage}, null, 2) : '';
      const passed = checks.filter((item) => item.passed === true).length;
      $('policy-candidate-summary').textContent = report
        ? `${report.candidate?.routes || 0} routes; ${passed}/${checks.length} dry-run checks passed${dryRunPassed ? '' : '; staging disabled'}; ${report.candidate?.policyHash || 'candidate hash unavailable'}`
        : 'Preview a candidate before staging it.';
    }

    function renderPolicyCanary() {
      const payload = state.policyCanary;
      const canary = payload?.canary;
      const running = canary?.status === 'running';
      $('policy-activate-button').disabled = !running;
      $('policy-cancel-button').disabled = !running;
      $('policy-canary-status').value = canary
        ? JSON.stringify({canary, monitoring: payload.monitoring}, null, 2)
        : 'No policy candidate is staged.';
    }

    async function stagePolicyCanary() {
      const candidate = state.policyCandidate;
      if (!candidate || !candidate.report) throw new Error('Preview and validate the signed candidate first');
      const checks = Array.isArray(candidate.report.dryRun?.results) ? candidate.report.dryRun.results : [];
      if (candidate.report.dryRun?.passed !== true || !checks.length || checks.some((item) => item.passed !== true)) {
        throw new Error('The signed candidate dry-run did not pass every check');
      }
      const active = await api('/api/policy');
      if (active.policy_hash !== candidate.basePolicyHash) throw new Error('Active policy changed after preview; generate a new candidate');
      const mutation = {
        kind: 'policy-canary',
        label: `Stage PolicyBundle route ${candidate.routeId}`,
        persist: true,
        path: '/api/policy/publish',
        method: 'POST',
        body: {bundle: candidate.bundle, dryRun: candidate.dryRun, activationMode: 'canary'}
      };
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }

    async function activatePolicyCanary() {
      const canary = state.policyCanary?.canary;
      if (!canary || canary.status !== 'running') throw new Error('No staged policy candidate is available to activate');
      const mutation = {
        kind: 'policy-canary-activate',
        label: `Activate staged policy candidate ${canary.id}`,
        persist: true,
        path: '/api/policy/canary/activate',
        method: 'POST',
        body: {canaryId: canary.id}
      };
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }

    async function cancelPolicyCanary() {
      const canary = state.policyCanary?.canary;
      if (!canary || canary.status !== 'running') throw new Error('No staged policy candidate is available to cancel');
      if (!window.confirm(`Cancel staged policy candidate ${canary.id}?`)) return cancelledAction('Policy candidate cancellation');
      const mutation = {
        kind: 'policy-canary-cancel',
        label: `Cancel staged policy candidate ${canary.id}`,
        persist: true,
        path: '/api/policy/canary/cancel',
        method: 'POST',
        body: {canaryId: canary.id, note: $('policy-canary-note').value.trim() || null}
      };
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }

    $('credential-kind').addEventListener('change', () => syncCredentialKindFields(true));

    $('credential-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Create credential', async () => {
        const form = new FormData(event.target);
        const kind = String(form.get('kind') || '');
        const metadata = JSON.parse(form.get('metadata') || '{}');
        const injectionNameValue = String(form.get('injectionName') || '').trim();
        if (kind === 'basic') metadata.username = injectionNameValue;
        if (['header', 'query', 'cookie'].includes(kind)) metadata.injection_name = injectionNameValue;
        storedCredentialInjection({id: 'new credential', kind, metadata});
        const mutation = {
          kind: 'credential-create',
          label: `Create credential ${form.get('name')}`,
          persist: false,
          path: '/api/credentials',
          method: 'POST',
          body: {name: form.get('name'), kind, secret: form.get('secret'), metadata}
        };
        const completed = await runControlPlaneMutation(mutation);
        if (!completed.pending) {
          event.target.reset();
          event.target.metadata.value = '{}';
          syncCredentialKindFields(true);
          await finishMutation(completed.mutation, completed.result);
        }
        return completed;
      });
    });

    $('oauth-provider').addEventListener('change', () => {
      $('oauth-scopes').value = '';
      renderOAuthDefaults(true);
      saveOAuthDraft();
    });

    function saveOAuthDraft() {
      const form = new FormData($('oauth-form'));
      sessionStorage.setItem(oauthDraftKey, JSON.stringify({
        provider: form.get('provider'),
        credentialName: form.get('credentialName'),
        scopes: form.get('scopes'),
        metadata: form.get('metadata')
      }));
    }

    function restoreOAuthDraft() {
      let draft = null;
      try { draft = JSON.parse(sessionStorage.getItem(oauthDraftKey) || 'null'); } catch (_) {}
      if (!draft) return;
      if (draft.provider && Array.from($('oauth-provider').options).some((item) => item.value === draft.provider && !item.disabled)) $('oauth-provider').value = draft.provider;
      $('oauth-credential-name').value = draft.credentialName || '';
      $('oauth-scopes').value = draft.scopes || '';
      $('oauth-metadata').value = draft.metadata || '{}';
      renderOAuthDefaults(false);
    }

    $('oauth-form').addEventListener('input', saveOAuthDraft);
    $('oauth-form').addEventListener('change', saveOAuthDraft);
    $('oauth-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Start OAuth login', async () => {
        const form = new FormData(event.target);
        const provider = (state.oauthProviders || []).find((item) => item.id === form.get('provider'));
        if (!provider || !provider.configured) throw new Error('The selected OAuth provider is not configured');
        const scopes = parseOAuthScopes(form.get('scopes'));
        const body = {provider: form.get('provider'), credentialName: form.get('credentialName') || null, scopes, metadata: JSON.parse(form.get('metadata') || '{}')};
        saveOAuthDraft();
        const mutation = {kind: 'oauth-start', label: `Connect ${provider.displayName}`, persist: true, path: '/api/oauth/start', method: 'POST', body};
        const completed = await runControlPlaneMutation(mutation);
        if (completed.pending) $('oauth-status').textContent = `Waiting for approval ${completed.approval.approvalId}.`;
        else await finishMutation(completed.mutation, completed.result);
        return completed;
      });
    });

    $('agent-enrollment-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Generate enrollment', async () => {
        const form = new FormData(event.target);
        const proxyEgressCidrs = parseProxyEgressCidrs(form.get('proxyEgressCidrs'));
        const enrollmentNonce = generateEnrollmentNonce();
        state.enrollmentPacket = await api('/api/agents/enrollment', {method: 'POST', body: JSON.stringify({
          principalId: form.get('principalId'), proxyUrl: form.get('proxyUrl'), controlPlaneUrl: form.get('controlPlaneUrl'), proxyEgressCidrs,
          namespace: form.get('namespace') || 'serverware-agents', caMountPath: form.get('caMountPath') || '/etc/serverware/serverware-ca.pem', podSelector: JSON.parse(form.get('podSelector') || '{}'),
          nonce: enrollmentNonce, ttlSeconds: 300
        })});
        renderEnrollmentOutput();
      });
    });

    $('policy-route-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Preview policy candidate', previewPolicyCandidate);
    });

    function auditSearchParams({exportMode = false} = {}) {
      const form = new FormData($('audit-search-form'));
      const params = new URLSearchParams({limit: exportMode ? '10000' : '100', scanLimit: exportMode ? '50000' : '5000'});
      for (const [key, rawValue] of form.entries()) {
        let value = String(rawValue || '').trim();
        if (!value) continue;
        if ((key === 'start' || key === 'end') && !Number.isNaN(new Date(value).getTime())) value = new Date(value).toISOString();
        params.set(key, value);
      }
      return params;
    }

    async function searchAudit() {
      state.auditSearchResult = await api(`/api/audit/search?${auditSearchParams()}`);
      renderAuditInvestigation();
      return state.auditSearchResult;
    }

    async function verifyAuditChain() {
      state.auditChain = await api('/api/audit/verify');
      renderAuditInvestigation();
      if (state.auditChain.ok !== true || state.auditChain.complete === false) throw new Error('Audit chain verification was incomplete or invalid');
      return state.auditChain;
    }

    async function downloadAuditExport() {
      const response = await fetch(`/api/audit/export?${auditSearchParams({exportMode: true})}`, {headers: adminHeaders()});
      if (!response.ok) {
        let detail = `Request failed with status ${response.status}`;
        try {
          const payload = await response.json();
          detail = typeof payload.detail === 'string' ? payload.detail : detail;
        } catch (_) {}
        throw new Error(detail);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'serverware-audit-export.jsonl';
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      return {downloaded: true};
    }

    $('audit-search-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Search audit', searchAudit);
    });
    $('control-plane-status-filter').addEventListener('change', renderControlPlaneApprovals);
    $('control-plane-search').addEventListener('input', renderControlPlaneApprovals);
    $('jit-approval-status-filter').addEventListener('change', renderJitApprovals);
    $('jit-approval-search').addEventListener('input', renderJitApprovals);

    $('policy-template').addEventListener('change', () => {
      const template = policyTemplates[$('policy-template').value];
      if (template) $('policy-route-id').value = template.routeId;
      syncPolicyTemplateEditor(true);
      renderPolicyCredentialOptions();
    });

    $('route-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Create local route', async () => {
        const form = new FormData(event.target);
        const injection = JSON.parse(form.get('injection') || '{}');
        injection.type = form.get('injection_type') || injection.type || 'bearer';
        const mutation = {
          kind: 'route-create', label: `Create local route ${form.get('name')}`, persist: false, path: '/api/routes', method: 'POST',
          body: {name: form.get('name'), enabled: form.get('enabled') === 'true', match_host: form.get('match_host'), match_path_prefix: form.get('match_path_prefix') || '/', credential_id: form.get('credential_id') || null, injection, policies: JSON.parse(form.get('policies') || '[]')}
        };
        const completed = await runControlPlaneMutation(mutation);
        if (!completed.pending) {
          event.target.reset();
          event.target.match_path_prefix.value = '/';
          event.target.injection.value = '{"type":"bearer"}';
          event.target.policies.value = '[{"type":"gmail_recent","days":30},{"type":"approval","ttl_seconds":30}]';
          await finishMutation(completed.mutation, completed.result);
        }
        return completed;
      });
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

    function renderEnrollmentOutput() {
      $('enrollment-output').value = state.enrollmentPacket ? JSON.stringify(state.enrollmentPacket, null, 2) : '';
    }

    async function copyEnrollment() {
      if (!state.enrollmentPacket) return;
      await navigator.clipboard.writeText(JSON.stringify(state.enrollmentPacket, null, 2));
    }

    function downloadEnrollment() {
      if (!state.enrollmentPacket) return;
      const principal = String(state.enrollmentPacket.principalId || 'agent').replace(/[^a-zA-Z0-9_.-]+/g, '-');
      const blob = new Blob([JSON.stringify(state.enrollmentPacket, null, 2) + '\n'], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `serverware-enrollment-${principal}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }

    async function deleteCredential(id) {
      if (!window.confirm(`Delete credential ${id}? Agents using it will fail closed.`)) return cancelledAction('Credential deletion');
      const mutation = {kind: 'credential-delete', label: `Delete credential ${id}`, persist: false, path: `/api/credentials/${id}`, method: 'DELETE', body: {}};
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }
    async function deleteRoute(id) {
      if (!window.confirm(`Delete local prototype route ${id}? Matching requests will be denied.`)) return cancelledAction('Route deletion');
      const mutation = {kind: 'route-delete', label: `Delete local route ${id}`, persist: false, path: `/api/routes/${id}`, method: 'DELETE', body: {}};
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }
    async function loadApprovalReview(id) {
      state.approvalReview = await api(`/api/approvals/${id}/review`);
      render();
      requestAnimationFrame(() => {
        $('approval-review').focus({preventScroll: true});
        $('approval-review').scrollIntoView({behavior: 'smooth', block: 'start'});
      });
    }
    function approvalReviewBlockReason(item) {
      const review = state.approvalReview;
      if (!review || review.id !== item.id) return 'Open review first';
      const flags = new Set(review.risk_flags || []);
      if (flags.has('approval_expired')) return 'Approval expired';
      if (flags.has('policy_hash_not_current')) return 'Policy changed; request a new approval';
      return '';
    }
    function reviewPill(flag) {
      const cls = flag === 'policy_hash_not_current' || flag === 'approval_expired' ? 'bad' : flag === 'policy_hash_current' || flag === 'one_use_grant' ? 'good' : 'warn';
      return `<span class="pill ${cls}">${esc(flag)}</span>`;
    }
    function renderApprovalReview() {
      const target = $('approval-review');
      const review = state.approvalReview;
      if (!review) {
        target.innerHTML = '<p class="muted">No approval selected</p>';
        return;
      }
      const retry = review.retry_semantics || {};
      const previous = (review.previous_similar_approvals || []).map((item) => `
        <tr>
          <td>${pill(item.status)}</td>
          <td><code>${esc(item.requested_at || '')}</code></td>
          <td>${esc(item.decision_note || '')}</td>
          <td><code>${esc(item.request_digest || '')}</code></td>
        </tr>`).join('') || '<tr><td colspan="4" class="muted">No similar approvals</td></tr>';
      target.innerHTML = `
        <div class="review-grid">
          <div class="review-field"><span>Approval</span><code>${esc(review.id)}</code>${pill(review.status)}</div>
          <div class="review-field"><span>Principal</span><code>${esc(review.principal_id)}</code></div>
          <div class="review-field"><span>Source</span><code class="json">${json(review.source_identity)}</code></div>
          <div class="review-field"><span>Route</span><code>${esc(review.route_id)}</code></div>
          <div class="review-field"><span>Credential</span><code>${esc(review.credential_ref)}@${esc(review.credential_version)}</code></div>
          <div class="review-field"><span>Policy</span><code>${esc(review.policy_hash)}</code></div>
          <div class="review-field"><span>Request</span><code>${esc(review.method)} ${esc(review.url)}</code></div>
          <div class="review-field"><span>Body hash</span><code>${esc(review.body_hash || '')}</code></div>
          <div class="review-field"><span>Request digest</span><code>${esc(retry.request_digest || '')}</code></div>
          <div class="review-field"><span>Operation digest</span><code>${esc(retry.operation_digest || '')}</code></div>
        </div>
        <div class="review-block">
          <h3>Risk flags</h3>
          <div class="toolbar">${(review.risk_flags || []).map(reviewPill).join('') || '<span class="muted">None</span>'}</div>
        </div>
        <div class="review-block">
          <h3>Operation</h3>
          <code class="json">${json(review.normalized_operation_fields)}</code>
        </div>
        <div class="review-block">
          <h3>Redacted payload</h3>
          <code class="json">${json(review.redacted_payload_summary)}</code>
        </div>
        <div class="review-block">
          <h3>Retry semantics</h3>
          <code class="json">${json(review.retry_semantics)}</code>
        </div>
        <div class="review-block">
          <h3>Previous similar approvals</h3>
          <table>
            <thead><tr><th>Status</th><th>Requested</th><th>Decision note</th><th>Request digest</th></tr></thead>
            <tbody>${previous}</tbody>
          </table>
        </div>`;
    }
    async function approve(id) {
      const item = state.approvals.find((approval) => approval.id === id) || {id};
      const blockReason = approvalReviewBlockReason(item);
      if (!state.approvalReview || state.approvalReview.id !== id) {
        await loadApprovalReview(id);
        setStatus(`Review loaded for approval ${id}.`, 'pending');
        return {pending: true, reviewLoaded: true};
      }
      if (blockReason) {
        setStatus(`Approval ${id} cannot be approved: ${blockReason}.`, 'error');
        return {blocked: true, reason: blockReason};
      }
      const options = await api(`/api/approvals/${id}/webauthn/options`, {method: 'POST'});
      let body = {};
      if (window.PublicKeyCredential && (options.publicKey.allowCredentials || []).length) {
        const assertion = await navigator.credentials.get({publicKey: prepareRequestOptions(options)});
        body.assertion = credentialToJson(assertion);
      }
      const grantTtlSeconds = Number(item.grant_ttl_seconds || state.approvalReview?.retry_semantics?.grant_ttl_seconds || 30);
      await api(`/api/approvals/${id}/approve?ttl_seconds=${encodeURIComponent(grantTtlSeconds)}`, {
        method: 'POST',
        body: JSON.stringify(body)
      });
      await refresh();
    }
    async function deny(id) {
      const reason = $(`jit-deny-note-${id}`)?.value.trim() || null;
      await api(`/api/approvals/${id}/deny`, {method: 'POST', body: JSON.stringify({reason})});
      await refresh();
    }
    function cancelledAction(label) {
      setStatus(`${label} cancelled.`);
      return {pending: true, cancelled: true};
    }
    async function seedDemo() {
      if (!window.confirm('Replace the local development demo data and advance its policy sequence?')) return cancelledAction('Demo seed');
      await api('/api/demo/seed', {method: 'POST'});
      await refresh();
    }
    async function clearLogs() {
      if (!window.confirm('Clear the local traffic log? The append-only audit chain is not deleted.')) return cancelledAction('Traffic log clear');
      await api('/api/logs', {method: 'DELETE'});
      await refresh();
    }
    async function registerPasskey() {
      if (!window.PublicKeyCredential) throw new Error('WebAuthn is not available in this browser');
      const body = {label: 'YubiKey'};
      if (state.webauthnBootstrapRequired) {
        const bootstrapToken = await requestWebAuthnBootstrapToken();
        if (!bootstrapToken) return cancelledAction('Passkey registration');
        body.bootstrapToken = bootstrapToken;
      }
      const mutation = {
        kind: 'webauthn-register-options',
        label: 'Authorize passkey registration',
        persist: false,
        path: '/api/webauthn/register/options',
        method: 'POST',
        body
      };
      const authorized = await runControlPlaneMutation(mutation);
      body.bootstrapToken = undefined;
      if (authorized.pending) return authorized;
      await completePasskeyRegistration(authorized.result);
      return authorized;
    }
    async function completePasskeyRegistration(options) {
      const credential = await navigator.credentials.create({publicKey: prepareCreationOptions(options)});
      await api('/api/webauthn/register/verify', {
        method: 'POST',
        body: JSON.stringify({label: 'YubiKey', response: credentialToJson(credential)})
      });
      await refresh();
    }
    function requestWebAuthnBootstrapToken() {
      const dialog = $('webauthn-bootstrap-dialog');
      const form = $('webauthn-bootstrap-form');
      const input = $('webauthn-bootstrap-token');
      return new Promise((resolve) => {
        let settled = false;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          form.removeEventListener('submit', submit);
          $('webauthn-bootstrap-cancel').removeEventListener('click', cancel);
          dialog.removeEventListener('cancel', cancel);
          input.value = '';
          if (dialog.open) dialog.close();
          resolve(value);
        };
        const submit = (event) => {
          event.preventDefault();
          finish(input.value);
        };
        const cancel = (event) => {
          event.preventDefault();
          finish(null);
        };
        form.addEventListener('submit', submit);
        $('webauthn-bootstrap-cancel').addEventListener('click', cancel);
        dialog.addEventListener('cancel', cancel);
        dialog.showModal();
        input.focus();
      });
    }
    function shellQuote(value) {
      return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
    }
    async function copyEnrollmentVerifier() {
      const packet = state.enrollmentPacket;
      if (!packet) throw new Error('Generate an enrollment packet first so the verifier is bound to its pins');
      const pinning = packet.pinning || {};
      const serverware = packet.serverware || {};
      const ca = packet.ca || {};
      if (!serverware.controlPlaneUrl || !pinning.policySigningKeyId || !pinning.rollbackEpoch || !ca.installPath) {
        throw new Error('Enrollment packet is missing required verifier bindings');
      }
      const command = [
        ': "${SERVERWARE_ADMIN_TOKEN:?Set SERVERWARE_ADMIN_TOKEN for the enrolled operator}"',
        `python3 scripts/verify_attestation.py --base ${shellQuote(serverware.controlPlaneUrl)} --admin-token "$SERVERWARE_ADMIN_TOKEN" --ca-out .tmp/serverware-ca.pem --expected-policy-key-hash ${shellQuote(pinning.policySigningKeyId)} --expected-rollback-epoch ${Number(pinning.rollbackEpoch)}`,
        `install -D -m 0644 .tmp/serverware-ca.pem ${shellQuote(ca.installPath)}`,
        `export HTTPS_PROXY=${shellQuote(serverware.proxyUrl)}`,
        `export HTTP_PROXY=${shellQuote(serverware.proxyUrl)}`
      ].join('\n');
      await navigator.clipboard.writeText(command);
      return {copied: true, principalId: packet.principalId};
    }
    $('admin-token').value = sessionStorage.getItem(tokenKey) || '';
    $('admin-token').addEventListener('change', async () => {
      if (adminToken()) sessionStorage.setItem(tokenKey, adminToken());
      else sessionStorage.removeItem(tokenKey);
      try {
        await refresh();
        restoreOAuthDraft();
        renderOAuthDefaults(true);
      } catch (_) {}
    });
    restorePendingMutation();
    refresh().then(() => {
      restoreOAuthDraft();
      const template = policyTemplates[$('policy-template').value];
      if (template && !$('policy-route-id').value) $('policy-route-id').value = template.routeId;
      syncPolicyTemplateEditor();
    }).catch(() => {});
    setInterval(() => refresh().catch(() => {}), 4000);
  </script>
</body>
</html>
"""
