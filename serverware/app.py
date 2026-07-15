from __future__ import annotations

import base64
import fcntl
import hmac
import html
import hashlib
import ipaddress
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
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode, urlunsplit

from fastapi import (
    Body,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
    ATOMIC_RELEASE_AUTHORIZATION_ENABLED,
    CONTROL_PLANE_TWO_PERSON_ACTIONS,
    CONTROL_PLANE_TWO_PERSON_REQUIRED,
    CONTROL_PLANE_TWO_PERSON_TTL_SECONDS,
    CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES,
    CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION,
    CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED,
    CA_INSTALL_SESSIONS_PATH,
    CA_INSTALL_SESSION_CLAIM_TTL_SECONDS,
    CA_INSTALL_SESSION_MAX_ENTRIES,
    CA_INSTALL_SESSION_RETENTION_SECONDS,
    CA_INSTALL_SESSION_TTL_SECONDS,
    DATA_PLANE_AUDIT_INGEST_TOKEN,
    DATA_PLANE_CREDENTIAL_LEASE_TOKEN,
    DATA_PLANE_GRANT_CONSUME_TOKEN,
    DATA_PLANE_INSTANCE_ID,
    DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
    DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND,
    DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN,
    DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    DEV_AUTHENTICATOR_ENABLED,
    DIRECT_CA_DOWNLOAD_ENABLED,
    EXPECTED_DATA_PLANE_BINARY_DIGEST,
    MITMPROXY_CONF_DIR,
    OAUTH_PENDING_CREDENTIAL_TTL_SECONDS,
    OIDC_LOGIN_STATE_TTL_SECONDS,
    POLICY_BUNDLE_PATH,
    POLICY_CANARY_BUNDLE_PATH,
    POLICY_CANARY_MAX_DENIALS,
    POLICY_CANARY_MIN_AUDIT_EVENTS,
    POLICY_CANARY_MIN_OBSERVATION_SECONDS,
    POLICY_CANARY_REQUIRED,
    POLICY_CANARY_STATE_PATH,
    POLICY_PUBLISH_DRY_RUN_REQUIRED,
    PUBLIC_URL,
    RBAC_BINDINGS_PATH,
    RELEASE_CHANNEL,
    RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS,
    RELEASE_AUTHORIZATION_RECONCILE_LIMIT,
    RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS,
    SECRET_LEASE_TTL_SECONDS,
    SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS,
    WEBAUTHN_BOOTSTRAP_TOKEN,
)
from serverware import db, grants, runtime
from serverware.auth import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    OIDC_SESSION_COOKIE_NAME,
    AdminIdentity,
    OIDCAuthError,
    OIDCAccessDenied,
    OIDCAuthoritativeStateError,
    admin_status,
    issue_csrf_cookie,
    oidc_identity_from_token,
    require_admin,
    require_role,
    rotate_generated_admin_token,
    validate_csrf_request,
)
from serverware.crypto import encrypt_credential_lease_envelope
from serverware.control_plane_startup import validate_control_plane_startup
from serverware.enrollment import (
    AgentEnrollmentError,
    build_agent_enrollment,
    canonical_control_plane_url,
    policy_principal_summaries,
)
from serverware.key_release import (
    KeyReleaseError,
    release_material,
    status as key_release_status,
)
from serverware.oauth import (
    OAUTH_REFRESH_SKEW_SECONDS,
    OAuthError,
    browser_cookie_name,
    consume_state,
    create_authorization_url,
    exchange_authorization_code,
    normalize_provider_id,
    provider_status,
    refresh_access_token,
    revoke_oauth_token,
    resolve_requested_scopes,
)
from serverware.operator_oidc import (
    OperatorOIDCError,
    browser_login_configured,
    complete_operator_login,
    start_operator_login,
)
from serverware.policy_bundle import (
    PolicyBundleError,
    compile_policy_bundle,
    demo_policy_bundle,
    get_policy_snapshot,
    policy_public_key_hash,
    policy_public_key_pem,
    sign_policy_bundle,
    write_policy_bundle,
)
from serverware.response_identity import response_signature_headers, response_statement
from serverware.setup_receipt_service import (
    SetupReceiptTrustConfigurationError,
    setup_receipt_trust_profile,
)
from serverware.setup_receipts import (
    EnrollmentReceiptExpected,
    FixedClock,
    HardwareVerificationExpected,
    JsonLimits,
    ReceiptVerificationError,
    SetupAssignment,
    VerifiedEnrollmentVerifierReceipt,
    VerifiedSetupHardwareVerification,
    canonical_json_bytes as setup_receipt_canonical_json_bytes,
    derive_setup_completion_identity,
    parse_strict_json_object,
    sha256_digest as setup_receipt_sha256_digest,
    verify_enrollment_verifier_receipt,
    verify_final_challenge_receipt,
    verify_setup_hardware_verification,
)
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
from serverware.webauthn_trust import (
    WebAuthnTrustError,
    status as webauthn_trust_status,
    write_trust_bundle,
)


app = FastAPI(title="Serverware", version=__version__)
_OAUTH_REVOCATION_RECONCILE_BATCH_SIZE = 8
_OAUTH_REVOCATION_RECONCILE_INTERVAL_SECONDS = 15
_oauth_revocation_worker_lock = threading.Lock()
_oauth_revocation_worker_started = False
_credential_lease_audit_lock = threading.Lock()
_credential_lease_audit_last: dict[tuple[str, str, str, str, str, str, str], float] = {}
_CREDENTIAL_LEASE_AUDIT_INTERVAL_SECONDS = 60.0
_CREDENTIAL_LEASE_REQUEST_MAX_BYTES = 96 * 1024
_CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES = 4 * 1024 * 1024
_CREDENTIAL_LEASE_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
_SIGNED_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
_CONTROL_PLANE_REQUEST_MAX_BYTES = 2 * 1024 * 1024
_RECIPIENT_ATTESTATION_MAX_BYTES = 64 * 1024
_SETUP_RECEIPT_MAX_BYTES = 64 * 1024
_SETUP_HARDWARE_ASSURANCE_MAX_BYTES = 512 * 1024
_SETUP_RECEIPT_ENVELOPE_LIMITS = JsonLimits(
    max_bytes=1024 * 1024,
    max_depth=20,
    max_object_keys=64,
    max_total_keys=1024,
    max_array_items=256,
    max_total_nodes=8192,
    max_string_bytes=768 * 1024,
)
_SETUP_HARDWARE_ASSURANCE_JSON_LIMITS = JsonLimits(
    max_bytes=_SETUP_HARDWARE_ASSURANCE_MAX_BYTES,
    max_depth=32,
    max_object_keys=256,
    max_total_keys=4096,
    max_array_items=1024,
    max_total_nodes=32768,
    max_string_bytes=256 * 1024,
)
_recipient_attestation_verifier_slots = threading.BoundedSemaphore(value=4)


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    try:
        validate_csrf_request(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    return await call_next(request)


@app.middleware("http")
async def bounded_control_plane_request_middleware(request: Request, call_next):
    raw_content_length = request.headers.get("content-length")
    if raw_content_length is not None:
        try:
            content_length = int(raw_content_length)
        except ValueError:
            return JSONResponse(
                status_code=400, content={"detail": "invalid Content-Length"}
            )
        if content_length < 0:
            return JSONResponse(
                status_code=400, content={"detail": "invalid Content-Length"}
            )
        if content_length > _CONTROL_PLANE_REQUEST_MAX_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "control-plane request exceeds 2 MiB"},
            )
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > _CONTROL_PLANE_REQUEST_MAX_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "control-plane request exceeds 2 MiB"},
                )
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
            return JSONResponse(
                status_code=503, content={"detail": "signed response exceeds 8 MiB"}
            )
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
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    provider: str = Field(min_length=1)
    credential_name: str | None = Field(default=None, alias="credentialName")
    credential_id: str | None = Field(
        default=None, max_length=512, alias="credentialId"
    )
    setup_session_id: str | None = Field(
        default=None,
        alias="setupSessionId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    setup_revision: int | None = Field(default=None, alias="setupRevision", ge=0)
    scopes: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    mfa: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_setup_binding(self) -> OAuthStartRequest:
        if (self.setup_session_id is None) != (self.setup_revision is None):
            raise ValueError(
                "setupSessionId and setupRevision must be provided together"
            )
        return self

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return db.validate_credential_metadata(value)


class OAuthPendingActivateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    mfa: dict[str, Any] | None = None
    setup_session_id: str | None = Field(
        default=None,
        alias="setupSessionId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    setup_revision: int | None = Field(default=None, alias="setupRevision", ge=0)

    @model_validator(mode="after")
    def validate_setup_binding(self) -> OAuthPendingActivateRequest:
        if (self.setup_session_id is None) != (self.setup_revision is None):
            raise ValueError(
                "setupSessionId and setupRevision must be provided together"
            )
        return self


class OAuthIssuanceUncertaintyResolveRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    confirmed_provider_revocation: bool = Field(alias="confirmedProviderRevocation")
    note: str = Field(min_length=1, max_length=2000)
    mfa: dict[str, Any] | None = None

    @model_validator(mode="after")
    def require_provider_revocation(self) -> OAuthIssuanceUncertaintyResolveRequest:
        if self.confirmed_provider_revocation is not True:
            raise ValueError("confirmedProviderRevocation must be true")
        return self


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
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    note: str | None = None
    assertion: dict[str, Any] | None = None
    review_receipt_id: str | None = Field(
        default=None,
        alias="reviewReceiptId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )


class ApprovalWebAuthnOptionsRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    review_receipt_id: str = Field(
        alias="reviewReceiptId",
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )


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
    canonical_request: dict[str, Any] = Field(
        default_factory=dict, alias="canonicalRequest"
    )
    redacted_display: dict[str, Any] = Field(
        default_factory=dict, alias="redactedDisplay"
    )
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

    activation_mode: str = Field(
        default="full", alias="activationMode", pattern="^(full|canary)$"
    )
    mfa: dict[str, Any] | None = None


class PolicyCanaryActivationRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    canary_id: str = Field(alias="canaryId", min_length=1)
    min_observation_seconds: int | None = Field(
        default=None, alias="minObservationSeconds", ge=0
    )
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
    bootstrap_token: str | None = Field(
        default=None, alias="bootstrapToken", max_length=1024
    )
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
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(min_length=1, max_length=128)
    event: dict[str, Any] = Field(default_factory=dict)


class DataPlaneAuditBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[DataPlaneAuditEvent] = Field(default_factory=list, max_length=200)


class CredentialLeaseRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    api_version: Literal["serverware.credentialLeaseRequest/v2"] = Field(
        alias="apiVersion"
    )
    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_id: str = Field(alias="credentialId", min_length=1, max_length=256)
    recipient_public_key: str = Field(
        alias="recipientPublicKey", min_length=1, max_length=43
    )
    recipient_key_id: str = Field(alias="recipientKeyId", min_length=1, max_length=71)
    recipient_nonce: str = Field(alias="recipientNonce", min_length=1, max_length=43)
    policy_hash: str = Field(alias="policyHash", min_length=1, max_length=71)
    data_plane_binary_digest: str = Field(
        alias="dataPlaneBinaryDigest", min_length=1, max_length=71
    )
    max_ttl_seconds: int = Field(alias="maxTtlSeconds", ge=1, le=10)
    recipient_attestation: dict[str, Any] | None = Field(
        default=None, alias="recipientAttestation"
    )

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
    attempt_id: str | None = Field(
        default=None, alias="attemptId", min_length=1, max_length=256
    )
    method: str = Field(default="UNKNOWN", min_length=1)
    url: str = Field(default="serverware://data-plane/jit", min_length=1)
    canonical_request: dict[str, Any] = Field(
        default_factory=dict, alias="canonicalRequest"
    )
    redacted_display: dict[str, Any] = Field(
        default_factory=dict, alias="redactedDisplay"
    )
    consume: bool = True


class DataPlaneRateLimitConsume(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    counter_key: str = Field(alias="counterKey", pattern=r"^sha256:[0-9a-f]{64}$")
    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_ref: str | None = Field(
        default=None, alias="credentialRef", max_length=256
    )
    credential_version: int = Field(alias="credentialVersion", ge=0)
    policy_hash: str = Field(alias="policyHash", pattern=r"^sha256:[0-9a-f]{64}$")
    constraint_id: str = Field(alias="constraintId", min_length=1, max_length=256)
    operation: str | None = Field(default=None, max_length=256)
    operation_context: dict[str, Any] = Field(
        default_factory=dict, alias="operationContext"
    )
    max_count: int = Field(alias="max", ge=1, le=1_000_000_000)
    window_seconds: int = Field(alias="windowSeconds", ge=1, le=31_536_000)
    consume: bool = True

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


class DataPlaneReleaseAuthorizationReserve(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    api_version: Literal["serverware.releaseAuthorizationReserve/v1"] = Field(
        alias="apiVersion"
    )
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=256)
    flow_id: str = Field(alias="flowId", min_length=1, max_length=256)
    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_ref: str | None = Field(
        default=None, alias="credentialRef", max_length=256
    )
    credential_version: int = Field(alias="credentialVersion", ge=0)
    policy_hash: str = Field(
        alias="policyHash", pattern=r"^sha256:[0-9a-f]{64}$"
    )
    request_digest: str = Field(
        alias="requestDigest", pattern=r"^sha256:[0-9a-f]{64}$"
    )
    operation_digest: str | None = Field(
        default=None,
        alias="operationDigest",
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    operation_context: dict[str, Any] = Field(
        default_factory=dict, alias="operationContext"
    )
    canonical_request: dict[str, Any] | None = Field(
        default=None, alias="canonicalRequest"
    )

    @model_validator(mode="after")
    def validate_canonical_payload_sizes(
        self,
    ) -> DataPlaneReleaseAuthorizationReserve:
        for name, value in (
            ("operationContext", self.operation_context),
            ("canonicalRequest", self.canonical_request),
        ):
            if value is None:
                continue
            try:
                encoded = json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be canonical JSON") from exc
            if len(encoded) > 64 * 1024:
                raise ValueError(f"{name} exceeds 64 KiB")
        return self


class DataPlaneReleaseAuthorizationDispatch(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    api_version: Literal["serverware.releaseAuthorizationDispatch/v1"] = Field(
        alias="apiVersion"
    )
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=256)
    binding_digest: str = Field(
        alias="bindingDigest", pattern=r"^sha256:[0-9a-f]{64}$"
    )


class DataPlaneReleaseAuthorizationComplete(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    api_version: Literal["serverware.releaseAuthorizationComplete/v1"] = Field(
        alias="apiVersion"
    )
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=256)
    binding_digest: str = Field(
        alias="bindingDigest", pattern=r"^sha256:[0-9a-f]{64}$"
    )
    outcome: Literal["forwarded", "not_forwarded", "unknown"]


class AgentEnrollmentCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    principal_id: str = Field(alias="principalId", min_length=1)
    proxy_url: str = Field(alias="proxyUrl", min_length=1)
    control_plane_url: str | None = Field(
        default=None, alias="controlPlaneUrl", min_length=1, max_length=2048
    )
    proxy_egress_cidrs: list[str] = Field(alias="proxyEgressCidrs", min_length=1)
    namespace: str = "serverware-agents"
    pod_selector: dict[str, str] = Field(default_factory=dict, alias="podSelector")
    ca_mount_path: str = Field(
        default="/etc/serverware/serverware-ca.pem", alias="caMountPath"
    )
    nonce: str = Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")
    ttl_seconds: int = Field(default=300, alias="ttlSeconds", ge=30, le=900)


class SetupVerificationRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    principal_id: str = Field(alias="principalId", min_length=1, max_length=256)
    route_id: str = Field(alias="routeId", min_length=1, max_length=256)
    credential_id: str = Field(alias="credentialId", min_length=1, max_length=256)
    route_policy_digest: str = Field(
        alias="routePolicyDigest",
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    nonce: str = Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")
    enrollment_session_id: str | None = Field(
        default=None,
        alias="enrollmentSessionId",
        min_length=18,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


class SetupSessionCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    template_id: str | None = Field(default=None, alias="templateId", max_length=512)
    principal_id: str | None = Field(default=None, alias="principalId", max_length=512)
    route_id: str | None = Field(default=None, alias="routeId", max_length=512)
    route_policy_digest: str | None = Field(
        default=None,
        alias="routePolicyDigest",
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    ttl_seconds: int | None = Field(
        default=None, alias="ttlSeconds", ge=300, le=604_800
    )

    @model_validator(mode="after")
    def validate_route_policy_binding(self) -> SetupSessionCreateRequest:
        if self.route_policy_digest is not None and self.route_id is None:
            raise ValueError("routePolicyDigest requires routeId")
        return self


class SetupSessionRevisionRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    expected_revision: int = Field(alias="expectedRevision", ge=0)


class SetupSessionHandoffRequest(SetupSessionRevisionRequest):
    assignee_id: str = Field(alias="assigneeId", min_length=1, max_length=512)


class SetupSessionCancelRequest(SetupSessionRevisionRequest):
    reason: str | None = Field(default=None, max_length=2000)


class SetupSessionCredentialRequest(SetupSessionRevisionRequest):
    credential_id: str = Field(alias="credentialId", min_length=1, max_length=512)


class SetupSessionCanaryRequest(SetupSessionRevisionRequest):
    canary_id: str = Field(alias="canaryId", min_length=1, max_length=512)


class SetupSessionEnrollmentRequest(SetupSessionRevisionRequest):
    enrollment_session_id: str = Field(
        alias="enrollmentSessionId",
        min_length=18,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    verifier_nonce: str = Field(
        alias="verifierNonce",
        min_length=32,
        max_length=256,
        pattern=r"^[A-Za-z0-9_-]+$",
    )


class SetupSessionVerifyRequest(SetupSessionRevisionRequest):
    nonce: str = Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")


class KeyReleaseVerify(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    material: str = Field(min_length=1)
    expected_policy_hash: str | None = Field(default=None, alias="expectedPolicyHash")
    expected_policy_sequence: int | None = Field(
        default=None, alias="expectedPolicySequence", ge=1
    )
    expected_policy_high_water_digest: str | None = Field(
        default=None, alias="expectedPolicyHighWaterDigest"
    )
    expected_ca_spki: str | None = Field(default=None, alias="expectedCaSpki")
    expected_rollback_epoch: int | None = Field(
        default=None, alias="expectedRollbackEpoch"
    )
    expected_release_channel: str | None = Field(
        default=None, alias="expectedReleaseChannel"
    )
    expected_provenance_digest: str | None = Field(
        default=None, alias="expectedProvenanceDigest"
    )
    expected_data_plane_binary_digest: str | None = Field(
        default=None, alias="expectedDataPlaneBinaryDigest"
    )


@app.on_event("startup")
def startup() -> None:
    validate_control_plane_startup()
    _drain_setup_session_audit_outbox()
    runtime.start_runtime_workers()
    runtime.start_audit_anchor_worker()
    runtime.start_decision_gate_ca_publisher()
    _start_oauth_revocation_reconciler()


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


@app.get("/api/auth/status")
def operator_auth_status(request: Request) -> dict[str, Any]:
    identity = None
    token = request.cookies.get(OIDC_SESSION_COOKIE_NAME)
    if token:
        try:
            identity = oidc_identity_from_token(token, auth_method="oidc-session")
        except (OIDCAuthError, OIDCAccessDenied, OIDCAuthoritativeStateError):
            identity = None
    return {
        "authenticated": identity is not None,
        "userId": identity.user_id if identity else None,
        "roles": sorted(identity.roles) if identity else [],
        "authMethod": identity.auth_method if identity else None,
        "oidcBrowserLoginConfigured": browser_login_configured(),
    }


def _operator_oidc_source_key(request: Request) -> str:
    client = getattr(request, "client", None)
    peer_host = getattr(client, "host", None)
    try:
        canonical_peer = ipaddress.ip_address(str(peer_host)).compressed
    except ValueError:
        canonical_peer = "unknown"
    return (
        "sha256:"
        + hashlib.sha256(
            f"serverware-oidc-peer:{canonical_peer}".encode("ascii")
        ).hexdigest()
    )


@app.get("/api/auth/oidc/start")
def operator_oidc_start(response: Response, request: Request) -> dict[str, Any]:
    source_key = _operator_oidc_source_key(request)
    try:
        with db.oidc_login_source(source_key):
            started = start_operator_login()
    except (OperatorOIDCError, db.MetadataStoreError, ValueError) as exc:
        detail = str(exc)
        status_code = (
            429 if "rate limit" in detail or "source capacity" in detail else 503
        )
        raise HTTPException(status_code=status_code, detail=detail) from exc
    response.set_cookie(
        "serverware_oidc_flow",
        started["browser_nonce"],
        max_age=OIDC_LOGIN_STATE_TTL_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/api/auth/oidc/callback",
    )
    db.record_audit_event(
        "control_plane.oidc_login.started",
        {
            "state_hash": started["state_hash"],
            "expires_at": started["expires_at"],
            "source_key": source_key,
        },
    )
    return {
        "authorizationUrl": started["authorization_url"],
        "expiresAt": started["expires_at"],
    }


@app.get("/api/auth/oidc/callback")
def operator_oidc_callback(
    request: Request,
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> Response:
    if error or not state or not code:
        raise HTTPException(
            status_code=400,
            detail="OIDC login was denied or returned an incomplete callback",
        )
    try:
        completed = complete_operator_login(
            state=state,
            code=code,
            browser_nonce=request.cookies.get("serverware_oidc_flow", ""),
        )
    except OperatorOIDCError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    identity = completed["identity"]
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        OIDC_SESSION_COOKIE_NAME,
        completed["id_token"],
        max_age=completed["max_age"],
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    response.delete_cookie("serverware_oidc_flow", path="/api/auth/oidc/callback")
    issue_csrf_cookie(response, request)
    db.record_audit_event(
        "control_plane.oidc_login.completed",
        {
            "user_id": identity.user_id,
            "roles": sorted(identity.roles),
            "expires_at_epoch": completed["expires_at"],
        },
        actor_id=identity.user_id,
    )
    return response


@app.post("/api/auth/logout")
def operator_logout(
    response: Response,
    request: Request,
    identity: AdminIdentity = Depends(require_admin),
) -> dict[str, Any]:
    response.delete_cookie(
        OIDC_SESSION_COOKIE_NAME,
        path="/",
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    db.record_audit_event(
        "control_plane.logout",
        {"auth_method": identity.auth_method},
        actor_id=identity.user_id,
    )
    return {"ok": True}


def _approval_jit_policy(
    approval: dict[str, Any], *, require_current_policy: bool = False
) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if require_current_policy and snapshot.hash != approval.get("policy_hash"):
        raise HTTPException(
            status_code=409,
            detail="active policy changed after approval request; request a new approval",
        )
    route = _active_route_by_id(str(approval.get("route_id") or ""), snapshot=snapshot)
    return route.jit or {}


def _active_route_by_id(route_id: str, *, snapshot: Any | None = None) -> Any:
    snapshot = snapshot or get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    route = next((item for item in snapshot.routes if item.id == route_id), None)
    if not route:
        raise HTTPException(
            status_code=409, detail="approval route is not in the active policy"
        )
    return route


def _approval_authn_policy(jit: dict[str, Any]) -> dict[str, Any]:
    return (jit.get("approvers") or {}).get("authn") or {}


def _assert_approver_allowed(identity: AdminIdentity, jit: dict[str, Any]) -> None:
    approvers = jit.get("approvers") or {}
    users = set(approvers.get("users") or [])
    if users and "*" not in users and identity.user_id not in users:
        raise HTTPException(
            status_code=403,
            detail="current user is not an allowed approver for this route",
        )


def _webauthn_required(authn_policy: dict[str, Any]) -> bool:
    return bool(authn_policy.get("webauthnRequired"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _decode_unpadded_base64url(
    value: str, *, field_name: str, expected_length: int
) -> bytes:
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise HTTPException(
            status_code=400, detail=f"{field_name} must be unpadded base64url"
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"{field_name} must be unpadded base64url"
        ) from exc
    if len(decoded) != expected_length:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must decode to exactly {expected_length} bytes",
        )
    if not hmac.compare_digest(
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("="), value
    ):
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must use canonical base64url encoding",
        )
    return decoded


async def _bounded_credential_lease_request(request: Request) -> CredentialLeaseRequest:
    _require_data_plane_token(
        request.headers.get("X-Serverware-Data-Plane-Token"),
        DATA_PLANE_CREDENTIAL_LEASE_TOKEN,
    )
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > _CREDENTIAL_LEASE_REQUEST_MAX_BYTES:
                raise HTTPException(
                    status_code=413, detail="credential lease request exceeds 96 KiB"
                )
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail="invalid Content-Length"
            ) from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _CREDENTIAL_LEASE_REQUEST_MAX_BYTES:
            body.clear()
            raise HTTPException(
                status_code=413, detail="credential lease request exceeds 96 KiB"
            )
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
        raise HTTPException(
            status_code=503,
            detail="production recipient attestation is not configured fail-closed",
        )
    if evidence is None:
        if DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED:
            raise HTTPException(
                status_code=403, detail="recipient attestation is required"
            )
        return
    if not DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND:
        raise HTTPException(
            status_code=503, detail="recipient attestation verifier is not configured"
        )
    try:
        command = shlex.split(DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND)
    except ValueError as exc:
        raise HTTPException(
            status_code=503, detail="recipient attestation verifier command is invalid"
        ) from exc
    if not command:
        raise HTTPException(
            status_code=503, detail="recipient attestation verifier is not configured"
        )

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
        raise HTTPException(
            status_code=503, detail="recipient attestation verifier is at capacity"
        )
    try:
        with (
            tempfile.TemporaryFile() as verifier_stdin,
            tempfile.TemporaryFile() as verifier_stdout,
        ):
            verifier_stdin.write(
                (_canonical_json(verifier_input) + "\n").encode("utf-8")
            )
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
                raise HTTPException(
                    status_code=503,
                    detail="recipient attestation verifier is unavailable",
                ) from exc
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
                    raise HTTPException(
                        status_code=503,
                        detail="recipient attestation verifier timed out",
                    )
                time.sleep(0.005)
            if return_code != 0:
                raise HTTPException(
                    status_code=403, detail="recipient attestation verification failed"
                )
            verifier_stdout.seek(0)
            verifier_output = verifier_stdout.read(_RECIPIENT_ATTESTATION_MAX_BYTES + 1)
    finally:
        _recipient_attestation_verifier_slots.release()
    try:
        verified = json.loads(verifier_output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="recipient attestation verifier returned invalid JSON",
        ) from exc
    if not isinstance(verified, dict):
        raise HTTPException(
            status_code=503,
            detail="recipient attestation verifier returned invalid JSON",
        )
    if verified.get("ok") is not True:
        raise HTTPException(
            status_code=403, detail="recipient attestation verification failed"
        )
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
        raise HTTPException(
            status_code=403, detail="recipient attestation binding mismatch"
        )
    if (
        RELEASE_CHANNEL.strip().lower() not in {"dev", "development"}
        and verified.get("debug") is not False
    ):
        raise HTTPException(
            status_code=403,
            detail="debug recipient attestation is not allowed for this release channel",
        )


def _control_plane_payload_digest(value: dict[str, Any]) -> str:
    return (
        "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    )


def _control_plane_mutation_authn_policy() -> dict[str, Any]:
    policy: dict[str, Any] = {"userVerification": "required"}
    if CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES:
        policy["allowedAuthenticatorClasses"] = list(
            CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES
        )
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
    value = (
        mfa.get("approvalId")
        or mfa.get("approval_id")
        or mfa.get("controlPlaneApprovalId")
    )
    return str(value) if value else None


def _control_plane_approval_roles(action: str) -> set[str]:
    if action.startswith("setup.attestation."):
        return {"attestation_reviewer"}
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
        raise HTTPException(
            status_code=403, detail=f"required role: {' or '.join(sorted(required))}"
        )


def _require_control_plane_two_person(
    *,
    action: str,
    resource_id: str | None,
    payload_digest: str,
    mfa: dict[str, Any] | None,
    identity: AdminIdentity,
    request: dict[str, Any],
    connection: Any | None = None,
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
            _connection=connection,
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


def _reconcile_oauth_revocations(
    *, limit: int = _OAUTH_REVOCATION_RECONCILE_BATCH_SIZE
) -> dict[str, int]:
    worker_id = f"oauth-reconciler-{os.getpid()}-{secrets.token_hex(8)}"
    claimed = db.claim_oauth_revocations(worker_id=worker_id, limit=limit)
    revoked = 0
    failed = 0
    uncertain = 0
    for item in claimed:
        if item["kind"] == "issuance_uncertain":
            db.record_audit_event(
                "credential.oauth_issuance_uncertain",
                {
                    "provider": item["provider_id"],
                    "source": item["source"],
                    "revocation_work_id": item["id"],
                    "result": "manual_provider_review_required",
                    "error": item["error"],
                },
                actor_id=str(item["actor_id"]),
                idempotency_key=f"oauth-issuance-uncertainty:{item['id']}",
            )
            reported = db.finish_oauth_issuance_uncertainty_report(
                item["id"],
                worker_id=worker_id,
            )
            if not reported.get("ok"):
                raise db.MetadataStoreError(
                    "OAuth issuance uncertainty report claim changed before completion"
                )
            uncertain += 1
            continue
        error = None
        try:
            token_secret = json.loads(item["secret"])
            if not isinstance(token_secret, dict):
                raise OAuthError("OAuth revocation material is malformed")
            revoke_oauth_token(
                provider_id=str(item["provider_id"]),
                token_secret=token_secret,
            )
        except (OAuthError, json.JSONDecodeError, TypeError, ValueError) as exc:
            error = str(exc)[:500] or type(exc).__name__
        if item["kind"] == "pending":
            result = db.finish_pending_oauth_revocation(
                item["id"],
                actor_id="oauth-reconciler",
                succeeded=error is None,
                error=error,
            )
        else:
            result = db.finish_oauth_revocation_work(
                item["id"],
                worker_id=worker_id,
                succeeded=error is None,
                error=error,
            )
            db.record_audit_event(
                (
                    "credential.oauth_exchange_revoked"
                    if error is None
                    else "credential.oauth_exchange_revocation_failed"
                ),
                {
                    "provider": item["provider_id"],
                    "source": item["source"],
                    "revocation_work_id": item["id"],
                    "result": "revoked" if error is None else "failed",
                    "retry_retained": error is not None,
                },
                actor_id=str(item["actor_id"]),
            )
        if result.get("ok"):
            revoked += 1
        else:
            failed += 1
    result = {
        "claimed": len(claimed),
        "revoked": revoked,
        "failed": failed,
    }
    if uncertain:
        result["uncertain"] = uncertain
    return result


def _oauth_revocation_reconciler_loop() -> None:
    while True:
        try:
            _reconcile_oauth_revocations()
        except Exception:
            pass
        time.sleep(_OAUTH_REVOCATION_RECONCILE_INTERVAL_SECONDS)


def _start_oauth_revocation_reconciler() -> None:
    global _oauth_revocation_worker_started
    with _oauth_revocation_worker_lock:
        if _oauth_revocation_worker_started:
            return
        worker = threading.Thread(
            target=_oauth_revocation_reconciler_loop,
            name="serverware-oauth-revocation",
            daemon=True,
        )
        worker.start()
        _oauth_revocation_worker_started = True


def _revoke_terminal_pending_oauth_credential(
    pending_credential_id: str,
    *,
    actor_id: str,
) -> dict[str, Any]:
    material = db.get_pending_oauth_revocation_material(pending_credential_id)
    if material is None:
        return {"ok": False, "reason": "pending_credential_not_revocable"}
    try:
        token_secret = json.loads(material["secret"])
        if not isinstance(token_secret, dict):
            raise OAuthError("OAuth credential is malformed")
        revoked = revoke_oauth_token(
            provider_id=str(material.get("review", {}).get("provider") or ""),
            token_secret=token_secret,
        )
    except (OAuthError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return db.finish_pending_oauth_revocation(
            pending_credential_id,
            actor_id=actor_id,
            succeeded=False,
            error=str(exc)[:500],
        )
    result = db.finish_pending_oauth_revocation(
        pending_credential_id,
        actor_id=actor_id,
        succeeded=True,
    )
    return {**result, "provider": revoked.get("provider")}


def _disconnect_credential(credential_id: str, *, actor_id: str) -> dict[str, bool]:
    with db.oauth_refresh_lock(credential_id):
        try:
            disconnect = db.begin_oauth_credential_disconnect(credential_id)
        except db.ManagedOAuthCredentialError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if disconnect.get("ok"):
            credential = disconnect["credential"]
            runtime.invalidate_secret_leases(credential_id)
            try:
                token_secret = json.loads(str(credential.get("secret") or ""))
                if not isinstance(token_secret, dict):
                    raise OAuthError("OAuth credential is malformed")
                revoke_oauth_token(
                    provider_id=str(disconnect["provider"]),
                    token_secret=token_secret,
                )
            except (OAuthError, json.JSONDecodeError, TypeError, ValueError) as exc:
                failed = db.finish_oauth_credential_disconnect(
                    credential_id,
                    expected_version=int(credential["credential_version"]),
                    actor_id=actor_id,
                    succeeded=False,
                    error=str(exc)[:500],
                )
                runtime.invalidate_secret_leases(credential_id)
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "oauth_provider_revocation_failed",
                        "credentialId": credential_id,
                        "lifecycleStatus": "revocation_failed",
                        "retryable": True,
                        "reason": failed.get("reason"),
                    },
                ) from exc
            finished = db.finish_oauth_credential_disconnect(
                credential_id,
                expected_version=int(credential["credential_version"]),
                actor_id=actor_id,
                succeeded=True,
            )
            if not finished.get("ok"):
                runtime.invalidate_secret_leases(credential_id)
                raise HTTPException(
                    status_code=409,
                    detail={"error": "oauth_disconnect_state_changed", **finished},
                )
            return {"deleted": True, "provider_revoked": True}
        if disconnect.get("reason") == "credential_not_managed_oauth":
            try:
                return {
                    "deleted": db.delete_credential(credential_id),
                    "provider_revoked": False,
                }
            except db.ManagedOAuthCredentialError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        if disconnect.get("reason") == "credential_not_found":
            return {"deleted": False, "provider_revoked": False}
        raise HTTPException(
            status_code=409,
            detail={"error": "credential_disconnect_failed", **disconnect},
        )


def _policy_ids(raw: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for item in raw.get(key) or []
        if isinstance(item, dict) and item.get("id")
    }


def _policy_diff(
    previous: dict[str, Any] | None, candidate: dict[str, Any]
) -> dict[str, Any]:
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
    old_meta = (
        previous.get("metadata") if isinstance(previous.get("metadata"), dict) else {}
    )
    new_meta = (
        candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    )
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


def _assert_policy_publish_monotonic(
    current: dict[str, Any] | None, candidate: dict[str, Any]
) -> None:
    if not current:
        return
    current_sequence = _policy_metadata_int(current, "sequence")
    candidate_sequence = _policy_metadata_int(candidate, "sequence")
    current_epoch = _policy_metadata_int(current, "rollbackEpoch")
    candidate_epoch = _policy_metadata_int(candidate, "rollbackEpoch")
    if candidate_epoch < current_epoch:
        raise HTTPException(
            status_code=409, detail="policy rollbackEpoch cannot decrease"
        )
    if candidate_sequence <= current_sequence:
        raise HTTPException(
            status_code=409, detail="policy sequence must increase monotonically"
        )


def _run_policy_dry_runs(
    snapshot: Any, cases: list[PolicyDryRunCase]
) -> dict[str, Any]:
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
        candidate = compile_policy_bundle(
            signed, verify_signature=True, validate_schema=True
        )
    except PolicyBundleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if enforce_monotonic:
        _assert_policy_publish_monotonic(current_raw, signed)
    dry_run_result = _run_policy_dry_runs(candidate, dry_run)
    if POLICY_PUBLISH_DRY_RUN_REQUIRED and not dry_run:
        raise HTTPException(
            status_code=412, detail="policy publish requires dry-run decision tests"
        )
    if not dry_run_result["passed"]:
        raise HTTPException(
            status_code=409,
            detail={"error": "policy dry-run failed", "dryRun": dry_run_result},
        )
    metadata = (
        signed.get("metadata") if isinstance(signed.get("metadata"), dict) else {}
    )
    current_metadata = (
        current_raw.get("metadata")
        if isinstance(current_raw, dict)
        and isinstance(current_raw.get("metadata"), dict)
        else {}
    )
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


def _policy_canary_activate_payload_digest(
    payload: PolicyCanaryActivationRequest,
) -> str:
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
        raise HTTPException(
            status_code=404, detail="mitmproxy CA has not been generated yet"
        )
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
        raise HTTPException(
            status_code=503, detail="CA install session state is unreadable"
        ) from exc
    if not isinstance(state, dict) or not isinstance(state.get("sessions"), dict):
        raise HTTPException(
            status_code=503, detail="CA install session state is invalid"
        )
    return state


def _write_ca_install_sessions(state: dict[str, Any]) -> None:
    CA_INSTALL_SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CA_INSTALL_SESSIONS_PATH.with_suffix(
        CA_INSTALL_SESSIONS_PATH.suffix + ".tmp"
    )
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    temporary.replace(CA_INSTALL_SESSIONS_PATH)


_CA_INSTALL_SESSION_THREAD_LOCK = threading.RLock()


@contextmanager
def _ca_install_sessions_lock():
    lock_path = Path(str(CA_INSTALL_SESSIONS_PATH) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with (
        _CA_INSTALL_SESSION_THREAD_LOCK,
        lock_path.open("a+", encoding="utf-8") as lock_file,
    ):
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _prune_ca_install_sessions(
    state: dict[str, Any], *, now: datetime | None = None
) -> bool:
    current = now or datetime.now(timezone.utc)
    sessions = state.setdefault("sessions", {})
    changed = False
    for session_id, raw_session in list(sessions.items()):
        if not isinstance(raw_session, dict):
            del sessions[session_id]
            changed = True
            continue
        session = raw_session
        expires_at = _parse_iso_datetime(session.get("expires_at"))
        status = session.get("status")
        if status == "consuming":
            claimed_at = _parse_iso_datetime(session.get("consume_claimed_at"))
            claim_stale = (
                claimed_at is None
                or claimed_at
                + timedelta(seconds=max(1, CA_INSTALL_SESSION_CLAIM_TTL_SECONDS))
                <= current
            )
            if claim_stale:
                session["status"] = (
                    "expired"
                    if expires_at is None or expires_at <= current
                    else "active"
                )
                session.pop("consume_claim_id", None)
                session.pop("consume_claimed_at", None)
                if session["status"] == "expired":
                    session["expired_at"] = (expires_at or current).isoformat()
                changed = True
                status = session["status"]
        if status == "active" and (expires_at is None or expires_at <= current):
            session["status"] = "expired"
            session["expired_at"] = (expires_at or current).isoformat()
            changed = True
            status = "expired"
        if status not in {"consumed", "expired"}:
            continue
        consume_outbox = session.get("consume_audit_outbox")
        if (
            status == "consumed"
            and isinstance(consume_outbox, dict)
            and consume_outbox.get("status") != "delivered"
        ):
            continue
        terminal_at = _parse_iso_datetime(
            (session.get("expires_at") or session.get("expired_at"))
            if status == "expired"
            else (session.get("consumed_at") or session.get("expires_at"))
        )
        if terminal_at is not None and (
            terminal_at
            + timedelta(seconds=max(0, CA_INSTALL_SESSION_RETENTION_SECONDS))
            <= current
        ):
            del sessions[session_id]
            changed = True
    return changed


def _ca_install_session_public(
    session: dict[str, Any], *, include_token: str | None = None
) -> dict[str, Any]:
    result = {
        "id": session.get("id"),
        "nonce": session.get("nonce"),
        "status": session.get("status"),
        "createdAt": session.get("created_at"),
        "expiresAt": session.get("expires_at"),
        "consumedAt": session.get("consumed_at"),
        "downloadUrl": f"/api/ca/install-sessions/{session.get('id')}/ca.pem",
        "policyUrl": f"/api/ca/install-sessions/{session.get('id')}/policy",
        "tokenHeader": "X-Serverware-CA-Install-Token",
        "installMethod": "verifier-mediated-attestation",
    }
    if include_token is not None:
        result["token"] = include_token
    return result


def _create_ca_install_session(
    *,
    created_by: str,
    nonce: str | None = None,
    ttl_seconds: int | None = None,
    policy_hash: str | None = None,
    principal_id: str | None = None,
    purpose: str = "ca-install",
) -> tuple[dict[str, Any], str]:
    _drain_ca_install_session_audit_outbox(max_entries=32)
    now = datetime.now(timezone.utc)
    bounded_ttl = min(
        CA_INSTALL_SESSION_TTL_SECONDS, ttl_seconds or CA_INSTALL_SESSION_TTL_SECONDS
    )
    if bounded_ttl < 30 or bounded_ttl > 900:
        raise HTTPException(
            status_code=503, detail="CA install session lifetime is invalid"
        )
    token = secrets.token_urlsafe(32)
    session_id = secrets.token_urlsafe(18)
    session = {
        "id": session_id,
        "nonce": nonce or secrets.token_urlsafe(24),
        "status": "active",
        "token_sha256": _sha256_text(token),
        "created_at": now.isoformat(),
        "created_by": created_by,
        "expires_at": (now + timedelta(seconds=bounded_ttl)).isoformat(),
        "consumed_at": None,
        "consumed_by": None,
        "policy_hash": policy_hash,
        "principal_id": principal_id,
        "purpose": purpose,
    }
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        _prune_ca_install_sessions(state, now=now)
        if CA_INSTALL_SESSION_MAX_ENTRIES < 1:
            raise HTTPException(
                status_code=503, detail="CA install session capacity is invalid"
            )
        if len(state.setdefault("sessions", {})) >= CA_INSTALL_SESSION_MAX_ENTRIES:
            _write_ca_install_sessions(state)
            raise HTTPException(
                status_code=429, detail="CA install session capacity reached"
            )
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
            "policy_hash": policy_hash,
            "principal_id": principal_id,
            "purpose": purpose,
        },
        actor_id=created_by,
    )
    return session, token


def _active_ca_install_session_unlocked(
    session_id: str, token: str | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not token:
        raise HTTPException(status_code=401, detail="CA install token required")
    state = _read_ca_install_sessions()
    if _prune_ca_install_sessions(state):
        _write_ca_install_sessions(state)
    session = state.setdefault("sessions", {}).get(session_id)
    if not isinstance(session, dict):
        raise HTTPException(status_code=404, detail="CA install session not found")
    if session.get("status") == "expired":
        raise HTTPException(status_code=410, detail="CA install session expired")
    if session.get("status") != "active":
        raise HTTPException(
            status_code=409, detail=f"CA install session is {session.get('status')}"
        )
    if not hmac.compare_digest(
        str(session.get("token_sha256") or ""), _sha256_text(token)
    ):
        raise HTTPException(status_code=403, detail="CA install token mismatch")
    return state, session


def _active_ca_install_session(
    session_id: str, token: str | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    with _ca_install_sessions_lock():
        return _active_ca_install_session_unlocked(session_id, token)


def _prepare_ca_install_session_consumption(
    session_id: str, token: str | None
) -> dict[str, Any]:
    with _ca_install_sessions_lock():
        if not token:
            raise HTTPException(status_code=401, detail="CA install token required")
        state = _read_ca_install_sessions()
        if _prune_ca_install_sessions(state):
            _write_ca_install_sessions(state)
        session = state.setdefault("sessions", {}).get(session_id)
        if not isinstance(session, dict):
            raise HTTPException(status_code=404, detail="CA install session not found")
        if not hmac.compare_digest(
            str(session.get("token_sha256") or ""), _sha256_text(token)
        ):
            raise HTTPException(status_code=403, detail="CA install token mismatch")
        status = session.get("status")
        if status == "expired":
            raise HTTPException(status_code=410, detail="CA install session expired")
        if status == "consumed":
            outbox = session.get("consume_audit_outbox")
            if isinstance(outbox, dict) and outbox.get("status") in {
                "pending",
                "delivering",
            }:
                return dict(session)
            raise HTTPException(
                status_code=409, detail="CA install session is consumed"
            )
        if status != "active":
            raise HTTPException(
                status_code=409, detail=f"CA install session is {status}"
            )
        consumed_at = _now_iso()
        outbox_id = f"ca-consume:{session_id}:{secrets.token_urlsafe(12)}"
        session["status"] = "consumed"
        session["consumed_at"] = consumed_at
        session["consumed_by"] = f"capability:ca-install-session:{session_id}"
        session["consume_audit_outbox"] = {
            "id": outbox_id,
            "status": "pending",
            "created_at": consumed_at,
        }
        _write_ca_install_sessions(state)
        return dict(session)


def _claim_ca_install_session_audit_delivery(
    session_id: str,
    token: str | None,
    *,
    internal: bool = False,
) -> tuple[dict[str, Any], str]:
    with _ca_install_sessions_lock():
        if not internal and not token:
            raise HTTPException(status_code=401, detail="CA install token required")
        state = _read_ca_install_sessions()
        session = state.setdefault("sessions", {}).get(session_id)
        if not isinstance(session, dict) or session.get("status") != "consumed":
            raise HTTPException(
                status_code=409, detail="CA install session is not durably consumed"
            )
        if not internal and not hmac.compare_digest(
            str(session.get("token_sha256") or ""),
            _sha256_text(str(token)),
        ):
            raise HTTPException(status_code=403, detail="CA install token mismatch")
        outbox = session.get("consume_audit_outbox")
        if not isinstance(outbox, dict):
            raise HTTPException(
                status_code=503,
                detail="CA install consumption audit outbox is unavailable",
            )
        if outbox.get("status") == "delivered":
            raise HTTPException(
                status_code=409, detail="CA install session is consumed"
            )
        if outbox.get("status") == "delivering":
            claimed_at = _parse_iso_datetime(outbox.get("claimed_at"))
            if claimed_at is not None and claimed_at + timedelta(
                seconds=max(1, CA_INSTALL_SESSION_CLAIM_TTL_SECONDS)
            ) > datetime.now(timezone.utc):
                raise HTTPException(
                    status_code=409,
                    detail="CA install consumption audit delivery is in progress",
                )
        delivery_claim_id = secrets.token_urlsafe(18)
        outbox["status"] = "delivering"
        outbox["claim_id"] = delivery_claim_id
        outbox["claimed_at"] = _now_iso()
        _write_ca_install_sessions(state)
        return dict(session), delivery_claim_id


def _finish_ca_install_session_audit_delivery(
    session_id: str,
    delivery_claim_id: str,
    *,
    event_hash: str,
) -> None:
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        session = state.setdefault("sessions", {}).get(session_id)
        outbox = (
            session.get("consume_audit_outbox") if isinstance(session, dict) else None
        )
        if (
            not isinstance(outbox, dict)
            or outbox.get("status") != "delivering"
            or outbox.get("claim_id") != delivery_claim_id
        ):
            raise HTTPException(
                status_code=409, detail="CA install consumption audit claim changed"
            )
        outbox["status"] = "delivered"
        outbox["delivered_at"] = _now_iso()
        outbox["event_hash"] = event_hash
        outbox.pop("claim_id", None)
        outbox.pop("claimed_at", None)
        _write_ca_install_sessions(state)


def _rollback_ca_install_session_audit_delivery(
    session_id: str, delivery_claim_id: str
) -> None:
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        session = state.setdefault("sessions", {}).get(session_id)
        outbox = (
            session.get("consume_audit_outbox") if isinstance(session, dict) else None
        )
        if (
            not isinstance(outbox, dict)
            or outbox.get("status") != "delivering"
            or outbox.get("claim_id") != delivery_claim_id
        ):
            return
        outbox["status"] = "pending"
        outbox.pop("claim_id", None)
        outbox.pop("claimed_at", None)
        _write_ca_install_sessions(state)


def _deliver_ca_install_session_consumption_audit(
    session_id: str,
    token: str | None,
    *,
    internal: bool = False,
) -> None:
    session, delivery_claim_id = _claim_ca_install_session_audit_delivery(
        session_id,
        token,
        internal=internal,
    )
    outbox = session["consume_audit_outbox"]
    outbox_id = str(outbox["id"])
    try:
        audit = db.record_audit_event(
            "ca.install_session.consumed",
            {
                "session_id": session_id,
                "consume_outbox_id": outbox_id,
                "nonce": session.get("nonce"),
                "install_method": "verifier-mediated-attestation",
                "token_sha256": session.get("token_sha256"),
                "policy_hash": session.get("policy_hash"),
                "principal_id": session.get("principal_id"),
                "purpose": session.get("purpose"),
            },
            actor_type="capability",
            actor_id=f"ca-install-session:{session_id}",
            idempotency_key=outbox_id,
        )
        _finish_ca_install_session_audit_delivery(
            session_id,
            delivery_claim_id,
            event_hash=str(audit["event_hash"]),
        )
    except Exception:
        _rollback_ca_install_session_audit_delivery(session_id, delivery_claim_id)
        raise


def _drain_ca_install_session_audit_outbox(*, max_entries: int) -> int:
    if max_entries < 1:
        return 0
    now = datetime.now(timezone.utc)
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        candidates: list[str] = []
        for session_id, session in state.setdefault("sessions", {}).items():
            if not isinstance(session, dict) or session.get("status") != "consumed":
                continue
            outbox = session.get("consume_audit_outbox")
            if not isinstance(outbox, dict):
                continue
            status = outbox.get("status")
            claimed_at = _parse_iso_datetime(outbox.get("claimed_at"))
            if status == "pending" or (
                status == "delivering"
                and (
                    claimed_at is None
                    or claimed_at
                    + timedelta(seconds=max(1, CA_INSTALL_SESSION_CLAIM_TTL_SECONDS))
                    <= now
                )
            ):
                candidates.append(str(session_id))
                if len(candidates) >= max_entries:
                    break
    delivered = 0
    for session_id in candidates:
        try:
            _deliver_ca_install_session_consumption_audit(
                session_id, None, internal=True
            )
        except Exception:
            continue
        delivered += 1
    return delivered


def _bind_enrollment_session_packet(session_id: str, packet: dict[str, Any]) -> None:
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        session = state.setdefault("sessions", {}).get(session_id)
        if (
            not isinstance(session, dict)
            or session.get("status") != "active"
            or session.get("purpose") != "agent-enrollment"
        ):
            raise HTTPException(
                status_code=503,
                detail="agent enrollment capability state is unavailable",
            )
        authenticity = (
            packet.get("authenticity")
            if isinstance(packet.get("authenticity"), dict)
            else {}
        )
        statement = (
            authenticity.get("statement")
            if isinstance(authenticity.get("statement"), dict)
            else {}
        )
        packet_sha256 = statement.get("packetSha256")
        if (
            not isinstance(packet_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", packet_sha256) is None
        ):
            raise HTTPException(
                status_code=503, detail="agent enrollment packet digest is unavailable"
            )
        assignments = []
        for route in packet.get("allowedRoutes") or []:
            if not isinstance(route, dict):
                continue
            route_id = route.get("id")
            credential_id = route.get("credentialRef")
            if isinstance(route_id, str) and isinstance(credential_id, str):
                credential = db.get_credential(credential_id, include_inactive=True)
                credential_version = (
                    int(credential.get("credential_version") or 0)
                    if isinstance(credential, dict)
                    else 0
                )
                if credential_version < 1:
                    raise HTTPException(
                        status_code=503,
                        detail="agent enrollment credential generation is unavailable",
                    )
                assignments.append(
                    {
                        "route_id": route_id,
                        "credential_id": credential_id,
                        "credential_version": credential_version,
                    }
                )
        session["enrollment_packet_sha256"] = packet_sha256
        session["allowed_assignments"] = assignments
        _write_ca_install_sessions(state)


def _read_policy_canary_state() -> dict[str, Any] | None:
    if not POLICY_CANARY_STATE_PATH.exists():
        return None
    try:
        state = json.loads(POLICY_CANARY_STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503, detail="policy canary state is unreadable"
        ) from exc
    if not isinstance(state, dict):
        raise HTTPException(status_code=503, detail="policy canary state is invalid")
    return state


def _write_policy_canary_state(state: dict[str, Any]) -> None:
    POLICY_CANARY_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_CANARY_STATE_PATH.with_suffix(
        POLICY_CANARY_STATE_PATH.suffix + ".tmp"
    )
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    temporary.replace(POLICY_CANARY_STATE_PATH)


def _write_policy_canary_bundle(signed_bundle: dict[str, Any]) -> None:
    POLICY_CANARY_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = POLICY_CANARY_BUNDLE_PATH.with_suffix(
        POLICY_CANARY_BUNDLE_PATH.suffix + ".tmp"
    )
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
    for key in (
        "latency_ms",
        "latencyMs",
        "duration_ms",
        "durationMs",
        "upstream_latency_ms",
        "upstreamLatencyMs",
    ):
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
    if not route_ids:
        signed_bundle = state.get("signed_bundle")
        if isinstance(signed_bundle, dict):
            route_ids.update(
                str(item["id"])
                for item in (signed_bundle.get("routes") or [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            )
    return route_ids


_POLICY_CANARY_EVIDENCE_EVENT_TYPES = {
    "data_plane.request.denied",
    "data_plane.request.streamed",
    "data_plane.response.blocked",
    "data_plane.response.released",
}


def _policy_canary_monitor(
    state: dict[str, Any], *, limit: int = 1000
) -> dict[str, Any]:
    started_at = _parse_iso_datetime(state.get("started_at")) or datetime.now(
        timezone.utc
    )
    route_filter = _policy_canary_route_filter(state)
    candidate_policy_hash = state.get("candidate_policy_hash")
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
        if event_type not in _POLICY_CANARY_EVIDENCE_EVENT_TYPES:
            continue
        if event.get("policy_hash") != candidate_policy_hash:
            continue
        route_id = _audit_event_route_id(event)
        if route_filter and route_id not in route_filter:
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
        "observationSeconds": max(
            0, int((datetime.now(timezone.utc) - started_at).total_seconds())
        ),
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
    metadata = (
        signed_bundle.get("metadata")
        if isinstance(signed_bundle.get("metadata"), dict)
        else {}
    )
    canary_id = _policy_canary_id(
        report["candidate"]["policyHash"], metadata.get("sequence")
    )
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
    required_observation = max(
        POLICY_CANARY_MIN_OBSERVATION_SECONDS, payload.min_observation_seconds or 0
    )
    required_events = max(POLICY_CANARY_MIN_AUDIT_EVENTS, payload.min_audit_events or 0)
    max_denials = (
        min(POLICY_CANARY_MAX_DENIALS, payload.max_denials)
        if payload.max_denials is not None
        else POLICY_CANARY_MAX_DENIALS
    )
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
    if monitor["complete"] is not True:
        raise HTTPException(
            status_code=412,
            detail={
                "error": "policy_canary_audit_scan_incomplete",
                "canaryId": state.get("id"),
                "requiredCompleteScan": True,
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


VALID_RBAC_ROLES = {
    "admin",
    "attestation_operator",
    "attestation_reviewer",
    "policy_author",
    "policy_publisher",
    "credential_owner",
    "approver",
    "auditor",
}


def _read_rbac_bindings() -> dict[str, Any]:
    if not RBAC_BINDINGS_PATH.exists():
        return {"version": "serverware.rbacBindings/v1", "subjects": {}}
    try:
        data = json.loads(RBAC_BINDINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503, detail="RBAC binding state is unreadable"
        ) from exc
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
        raise HTTPException(
            status_code=400, detail={"error": "invalid_rbac_roles", "roles": invalid}
        )
    if not normalized:
        raise HTTPException(
            status_code=400, detail="at least one RBAC role is required"
        )
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
    request = (
        canonical.get("request") if isinstance(canonical.get("request"), dict) else {}
    )
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
    for key in (
        "client_ip",
        "clientIp",
        "client_cert_sha256",
        "clientCertSha256",
        "spiffe_id",
        "spiffeId",
    ):
        if canonical.get(key):
            result[key] = canonical[key]
    principal = canonical.get("principal") or canonical.get("principal_id")
    if principal:
        result["principal"] = principal
    if canonical.get("proxy_authorization_hash") or canonical.get(
        "proxyAuthorizationHash"
    ):
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


def _approval_retry_semantics(
    approval: dict[str, Any], jit: dict[str, Any]
) -> dict[str, Any]:
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
        flags.append(
            "policy_hash_current"
            if snapshot and snapshot.hash == approval.get("policy_hash")
            else "policy_hash_not_current"
        )
    authn = _approval_authn_policy(jit)
    if _webauthn_required(authn):
        flags.append("webauthn_required")
    if authn.get("requireHardwareAttestation"):
        flags.append("hardware_attestation_required")
    if int(approval.get("grant_max_uses") or jit.get("maxUses") or 1) == 1:
        flags.append("one_use_grant")
    return flags


def _approval_history_item(item: dict[str, Any]) -> dict[str, Any]:
    authn = (
        item.get("approval_authn")
        if isinstance(item.get("approval_authn"), dict)
        else {}
    )
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
    canonical = (
        approval.get("canonical_request")
        if isinstance(approval.get("canonical_request"), dict)
        else {}
    )
    redacted_display = (
        approval.get("redacted_display")
        if isinstance(approval.get("redacted_display"), dict)
        else {}
    )
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
        "previous_similar_approvals": [
            _approval_history_item(item) for item in similar
        ],
        "retry_semantics": _approval_retry_semantics(approval, jit),
    }


@app.get("/attestation")
def attestation(nonce: str | None = None) -> dict[str, Any]:
    return attestation_document(nonce)


@app.post("/api/ca/install-sessions")
def ca_install_session_create(
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    session, token = _create_ca_install_session(
        created_by=identity.user_id,
        policy_hash=snapshot.hash if snapshot is not None else None,
    )
    return {
        "ok": True,
        "session": _ca_install_session_public(session, include_token=token),
    }


@app.get("/api/ca/install-sessions/{session_id}/policy")
def ca_install_session_policy(
    session_id: str,
    x_serverware_ca_install_token: str | None = Header(
        default=None, alias="X-Serverware-CA-Install-Token"
    ),
) -> dict[str, Any]:
    _, session = _active_ca_install_session(session_id, x_serverware_ca_install_token)
    result = _policy_status_document()
    expected_policy_hash = session.get("policy_hash")
    if expected_policy_hash and result.get("policy_hash") != expected_policy_hash:
        raise HTTPException(status_code=409, detail="CA install session policy changed")
    return result


@app.get("/api/ca/install-sessions/{session_id}/ca.pem")
def ca_install_session_download(
    session_id: str,
    x_serverware_ca_install_token: str | None = Header(
        default=None, alias="X-Serverware-CA-Install-Token"
    ),
) -> FileResponse:
    if not _ca_cert_path().exists():
        raise HTTPException(
            status_code=404, detail="mitmproxy CA has not been generated yet"
        )
    _prepare_ca_install_session_consumption(session_id, x_serverware_ca_install_token)
    _deliver_ca_install_session_consumption_audit(
        session_id, x_serverware_ca_install_token
    )
    return _ca_file_response(headers={"X-Serverware-CA-Install-Session": session_id})


@app.get("/api/release/provenance")
def release_provenance_api(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    document = release_provenance_document()
    if document is None:
        raise HTTPException(
            status_code=404, detail="release provenance has not been published"
        )
    return document


@app.get("/api/release/image-signatures")
def image_signatures_api(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    document = image_signatures_document()
    if document is None:
        raise HTTPException(
            status_code=404, detail="image signatures have not been published"
        )
    return document


@app.get("/ca.pem")
def ca_pem(identity: AdminIdentity = Depends(require_role("admin"))) -> FileResponse:
    if not DIRECT_CA_DOWNLOAD_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="direct CA download is disabled; use verifier-mediated install sessions",
        )
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
def key_release_status_api(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
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
    can_view_routes = identity.has_any_role(
        {"policy_author", "policy_publisher", "auditor"}
    )
    can_view_approvals = identity.has_any_role({"approver", "auditor"})
    can_view_logs = identity.has_any_role({"auditor"})
    credentials = db.list_credentials() if can_view_credentials else []
    pending_oauth_credentials = (
        db.list_pending_oauth_credentials(
            requester_id=(
                None
                if identity.has_any_role({"admin"})
                else identity.user_id
            )
        )
        if can_view_credentials
        else []
    )
    oauth_issuance_uncertainties = (
        db.list_oauth_issuance_uncertainties(
            actor_id=None if identity.has_any_role({"admin"}) else identity.user_id
        )
        if can_view_credentials
        else []
    )
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
        "pendingOAuthCredentials": pending_oauth_credentials,
        "oauthIssuanceUncertainties": oauth_issuance_uncertainties,
        "routes": routes,
        "approvals": approvals,
        "logs": logs,
        "ca_ready": (MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem").exists(),
        "policy_ready": snapshot is not None,
        "policy_hash": snapshot.hash if snapshot else None,
        "policy_signature": metadata.get("signature")
        if isinstance(metadata, dict)
        else None,
        "policy_signing_key_id": metadata.get("signingKeyId")
        if isinstance(metadata, dict)
        else None,
        "policy_path": str(POLICY_BUNDLE_PATH),
        "publicUrl": canonical_control_plane_url(PUBLIC_URL),
        "policyPrincipals": policy_principals,
        "oauthProviders": provider_status() if can_view_credentials else [],
        "currentUserId": identity.user_id,
        "currentUserRoles": sorted(identity.roles),
        "webauthnCredentialCount": webauthn_credential_count,
        "webauthnBootstrapRequired": (
            webauthn_credential_count == 0
            and RELEASE_CHANNEL.strip().lower()
            not in {"dev", "development", "local", "test"}
        ),
        **admin_status(),
    }
    db.record_audit_event(
        "control_plane.bootstrap",
        {
            "policy_hash": snapshot.hash if snapshot else None,
            "counts": {
                "credentials": len(credentials),
                "pending_oauth_credentials": len(pending_oauth_credentials),
                "oauth_issuance_uncertainties": len(oauth_issuance_uncertainties),
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
def csrf_token(
    response: Response, request: Request, _: AdminIdentity = Depends(require_admin)
) -> dict[str, Any]:
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
    identity: AdminIdentity = Depends(
        require_role(
            "admin", "policy_author", "policy_publisher", "credential_owner", "approver"
        )
    ),
) -> dict[str, Any]:
    return control_plane_mutation_options(
        user_id=identity.user_id,
        action=payload.action,
        resource_id=payload.resource_id,
        payload_digest=payload.payload_digest,
        authn_policy=_control_plane_mutation_authn_policy(),
    )


@app.get("/api/rbac/role-bindings")
def rbac_role_bindings(
    _: AdminIdentity = Depends(require_role("admin", "auditor")),
) -> dict[str, Any]:
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
    previous = (
        subjects.get(subject_id) if isinstance(subjects.get(subject_id), dict) else {}
    )
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
    previous = (
        subjects.get(payload.subject_id)
        if isinstance(subjects.get(payload.subject_id), dict)
        else {}
    )
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
    request_payload = (
        payload
        if isinstance(payload, AdminTokenRotateRequest)
        else AdminTokenRotateRequest()
    )
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
    _: AdminIdentity = Depends(
        require_role("auditor", "policy_publisher", "credential_owner", "policy_author")
    ),
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
        raise HTTPException(
            status_code=409,
            detail=f"control-plane approval is already {approval['status']}",
        )
    if approval["requester_id"] == identity.user_id:
        raise HTTPException(
            status_code=403,
            detail="requester cannot approve their own control-plane mutation",
        )
    _assert_control_plane_approval_role(identity, approval["action"])
    updated = db.approve_control_plane_approval(
        approval_id,
        actor_id=identity.user_id,
        note=decision.note if decision else None,
        authn={"method": identity.auth_method, "user_id": identity.user_id},
    )
    if not updated:
        raise HTTPException(
            status_code=409,
            detail="control-plane approval state changed before it could be approved",
        )
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
        raise HTTPException(
            status_code=409,
            detail=f"control-plane approval is already {approval['status']}",
        )
    _assert_control_plane_approval_role(identity, approval["action"])
    updated = db.deny_control_plane_approval(
        approval_id,
        actor_id=identity.user_id,
        note=decision.note if decision else None,
    )
    if not updated:
        raise HTTPException(
            status_code=409,
            detail="control-plane approval state changed before it could be denied",
        )
    if updated["action"] == "credential.oauth.activate" and updated.get("resource_id"):
        updated = {
            **updated,
            "oauthRevocation": _revoke_terminal_pending_oauth_credential(
                updated["resource_id"],
                actor_id=identity.user_id,
            ),
        }
    return updated


@app.post("/api/policy/candidate")
def policy_candidate(
    payload: PolicyCandidateRequest,
    _: AdminIdentity = Depends(require_role("policy_author", "policy_publisher")),
) -> dict[str, Any]:
    return _policy_candidate_report(
        bundle=payload.bundle, dry_run=payload.dry_run, enforce_monotonic=False
    )


@app.post("/api/policy/publish")
def policy_publish(
    payload: PolicyPublishRequest,
    identity: AdminIdentity = Depends(require_role("policy_publisher")),
) -> dict[str, Any]:
    report = _policy_candidate_report(
        bundle=payload.bundle, dry_run=payload.dry_run, enforce_monotonic=True
    )
    metadata = (
        report["signedBundle"].get("metadata")
        if isinstance(report["signedBundle"].get("metadata"), dict)
        else {}
    )
    policy_id = metadata.get("id")
    payload_digest = _policy_publish_payload_digest(payload)
    if payload.activation_mode == "full" and POLICY_CANARY_REQUIRED:
        raise HTTPException(
            status_code=412,
            detail="policy canary activation is required before full publish",
        )
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
    _: AdminIdentity = Depends(
        require_role("auditor", "policy_publisher", "policy_author")
    ),
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
        raise HTTPException(
            status_code=409, detail=f"policy canary is {state.get('status')}"
        )
    signed_bundle = state.get("signed_bundle")
    if not isinstance(signed_bundle, dict):
        raise HTTPException(
            status_code=503, detail="policy canary signed bundle is missing"
        )
    try:
        candidate = compile_policy_bundle(
            signed_bundle, verify_signature=True, validate_schema=True
        )
    except PolicyBundleError as exc:
        raise HTTPException(
            status_code=409, detail=f"policy canary bundle is invalid: {exc}"
        ) from exc
    if candidate.hash != state.get("candidate_policy_hash"):
        raise HTTPException(
            status_code=409, detail="policy canary bundle hash no longer matches state"
        )
    current = get_policy_snapshot()
    current_hash = current.hash if current else None
    if current_hash != state.get("previous_policy_hash"):
        raise HTTPException(
            status_code=409, detail="active policy changed after canary start"
        )
    _assert_policy_publish_monotonic(current.raw if current else None, signed_bundle)
    monitor = _policy_canary_monitor(state)
    thresholds = _require_policy_canary_activation_thresholds(state, monitor, payload)
    payload_digest = _policy_canary_activate_payload_digest(payload)
    metadata = (
        signed_bundle.get("metadata")
        if isinstance(signed_bundle.get("metadata"), dict)
        else {}
    )
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
        "previous_sequence": (current.raw.get("metadata") or {}).get("sequence")
        if current
        else None,
        "new_sequence": metadata.get("sequence"),
        "previous_rollback_epoch": (current.raw.get("metadata") or {}).get(
            "rollbackEpoch"
        )
        if current
        else None,
        "new_rollback_epoch": metadata.get("rollbackEpoch"),
        "diff": state.get("diff"),
        "dry_run": state.get("dry_run"),
        "canary_monitoring": monitor,
        "canary_thresholds": thresholds,
        "control_plane_mfa": mfa,
        "control_plane_approval": two_person,
        "payload_digest": payload_digest,
    }
    db.record_audit_event(
        "policy.canary.activated", audit_payload, actor_id=identity.user_id
    )
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
        raise HTTPException(
            status_code=409, detail=f"policy canary is {state.get('status')}"
        )
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


def _setup_check(
    check_id: str,
    *,
    passed: bool,
    summary: str,
    required: bool = True,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "pass" if passed else ("fail" if required else "pending"),
        "required": required,
        "summary": summary,
        **({"evidence": evidence} if evidence else {}),
    }


def _setup_audit_evidence_candidates(
    event_type: str,
    *,
    principal_id: str,
    route_id: str,
    policy_hash: str,
    credential_id: str,
    credential_version: int,
    start: str,
    actor_type: str,
    enrollment_session_id: str | None = None,
) -> list[dict[str, Any]]:
    result = db.search_audit_events(
        limit=1000,
        scan_limit=50000,
        event_type=event_type,
        actor_type=actor_type,
        principal_id=principal_id,
        route_id=route_id,
        policy_hash=policy_hash,
        credential_id=credential_id,
        credential_version=credential_version,
        start=start,
    )
    if not isinstance(result, dict) or result.get("complete") is not True:
        return []
    items = result.get("items") if isinstance(result, dict) else None
    if not isinstance(items, list):
        return []
    evidence: list[dict[str, Any]] = []
    for item in items:
        event = item.get("event") if isinstance(item.get("event"), dict) else {}
        event_enrollment_session_id = event.get("enrollment_session_id") or event.get(
            "enrollmentSessionId"
        )
        if (
            enrollment_session_id is not None
            and event_enrollment_session_id != enrollment_session_id
        ):
            continue
        evidence.append(
            {
                "eventType": item.get("event_type"),
                "createdAt": item.get("created_at"),
                "eventHash": item.get("event_hash"),
                "actorType": item.get("actor_type"),
                "enrollmentSessionId": event_enrollment_session_id,
                "requestDigest": event.get("request_digest")
                or event.get("requestDigest"),
                "operationDigest": event.get("operation_digest")
                or event.get("operationDigest"),
                "flowId": event.get("flow_id") or event.get("flowId"),
                "grantId": event.get("grant_id") or event.get("grantId"),
                "approvalId": (
                    event.get("approval_id")
                    or event.get("approvalId")
                    or event.get("approval_request_id")
                    or event.get("approvalRequestId")
                ),
                "consumptionId": event.get("consumption_id")
                or event.get("consumptionId"),
                "outcome": event.get("outcome"),
                "upstreamStatus": event.get("upstream_status")
                or event.get("upstreamStatus"),
                "responseBodySha256": event.get("response_body_sha256")
                or event.get("responseBodySha256"),
                "responseValidation": event.get("response_validation")
                if "response_validation" in event
                else event.get("responseValidation"),
            }
        )
    return evidence


def _setup_enrollment_session_evidence(
    payload: SetupVerificationRequest,
    *,
    policy_hash: str,
    credential_version: int,
) -> dict[str, Any] | None:
    if not payload.enrollment_session_id:
        return None
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        raw_session = state.get("sessions", {}).get(payload.enrollment_session_id)
        session = dict(raw_session) if isinstance(raw_session, dict) else None
    if not isinstance(session, dict):
        return None
    assignments = session.get("allowed_assignments")
    assignment_matches = (
        isinstance(assignments, list)
        and {
            "route_id": payload.route_id,
            "credential_id": payload.credential_id,
            "credential_version": credential_version,
        }
        in assignments
    )
    consumed_at = _parse_iso_datetime(session.get("consumed_at"))
    if not (
        session.get("purpose") == "agent-enrollment"
        and session.get("status") == "consumed"
        and session.get("principal_id") == payload.principal_id
        and session.get("policy_hash") == policy_hash
        and assignment_matches
        and isinstance(session.get("enrollment_packet_sha256"), str)
        and consumed_at is not None
        and consumed_at <= datetime.now(timezone.utc)
    ):
        return None
    return {
        "sessionId": session.get("id"),
        "enrollmentPacketSha256": session.get("enrollment_packet_sha256"),
        "consumedAt": consumed_at.isoformat(),
        "evidenceNotBefore": consumed_at.isoformat(),
    }


def _setup_credential_binding_checks(
    *,
    snapshot: Any,
    route: Any | None,
    credential: dict[str, Any] | None,
    credential_id: str,
) -> list[dict[str, Any]]:
    policy_credential = snapshot.credentials.get(credential_id)
    checks = [
        _setup_check(
            "credential.active",
            passed=credential is not None
            and credential.get("lifecycle_status", "active") == "active",
            summary="Credential exists in the active lifecycle state.",
            evidence=(
                {
                    "credentialId": credential_id,
                    "credentialVersion": credential.get("credential_version"),
                    "kind": credential.get("kind"),
                }
                if credential is not None
                else None
            ),
        ),
        _setup_check(
            "credential.policyDeclaration",
            passed=policy_credential is not None,
            summary="Credential is declared by the active signed policy.",
        ),
        _setup_check(
            "credential.routeBinding",
            passed=route is not None and route.credential_ref == credential_id,
            summary="Route references the selected credential exactly.",
        ),
    ]
    if credential is None or policy_credential is None:
        checks.extend(
            [
                _setup_check(
                    "credential.injectionBinding",
                    passed=False,
                    summary="Stored and signed-policy injection shapes must agree.",
                ),
                _setup_check(
                    "credential.providerBinding",
                    passed=False,
                    summary="Managed OAuth identity and signed-policy provider bindings must agree.",
                ),
                _setup_check(
                    "credential.scopeBinding",
                    passed=False,
                    summary="The active policy may use only scopes granted to the selected credential.",
                ),
            ]
        )
        return checks

    metadata = (
        credential.get("metadata")
        if isinstance(credential.get("metadata"), dict)
        else {}
    )
    stored_kind = str(credential.get("kind") or "")
    injection = (
        policy_credential.injection
        if isinstance(policy_credential.injection, dict)
        else {}
    )
    injection_type = str(injection.get("type") or "")
    expected_type = "bearer" if stored_kind == "oauth2" else stored_kind
    injection_matches = bool(injection_type) and injection_type == expected_type
    if injection_matches and stored_kind == "oauth2":
        injection_matches = (
            str(injection.get("header") or "Authorization").lower() == "authorization"
            and injection.get("field") == "access_token"
        )
    if injection_matches and injection_type in {"header", "query", "cookie"}:
        injection_matches = injection.get("name") == metadata.get("injection_name")
    if injection_matches and injection_type == "basic":
        injection_matches = bool(metadata.get("username")) and injection.get(
            "username"
        ) == metadata.get("username")
    if injection_matches and metadata.get("injection_field") is not None:
        injection_matches = injection.get("field") == metadata.get("injection_field")
    if injection_matches and metadata.get("injection_prefix") is not None:
        injection_matches = injection.get("prefix") == metadata.get("injection_prefix")
    checks.append(
        _setup_check(
            "credential.injectionBinding",
            passed=injection_matches,
            summary="Stored and signed-policy injection shapes agree.",
            evidence={
                "storedKind": stored_kind,
                "policyInjectionType": injection_type or None,
            },
        )
    )

    managed_oauth = stored_kind == "oauth2" or metadata.get("oauth") is True
    if not managed_oauth:
        checks.extend(
            [
                _setup_check(
                    "credential.providerBinding",
                    passed=True,
                    summary="Static credential does not require an OAuth subject binding.",
                    evidence={"provider": policy_credential.provider},
                ),
                _setup_check(
                    "credential.scopeBinding",
                    passed=True,
                    summary="Static credential has no mutable OAuth grant scope set.",
                ),
            ]
        )
        return checks

    provider_binding = False
    provider_id = None
    provider_subject = None
    try:
        provider_id, provider_subject, _ = db.validate_managed_oauth_account_identity(
            metadata
        )
        normalized_provider_id = _normalized_credential_provider(provider_id)
        policy_provider = _normalized_credential_provider(policy_credential.provider)
        provider_binding = (
            metadata.get("provider_identity_verified") is True
            and normalized_provider_id == policy_provider
            and policy_credential.provider_subject == provider_subject
        )
        if provider_binding and normalized_provider_id == "x":
            app_id = metadata.get("x_app_id") or metadata.get("app_id")
            configured_app_ids = (
                route.adapter_config.get("appIds") if route is not None else None
            )
            provider_binding = (
                isinstance(app_id, str)
                and bool(app_id)
                and isinstance(configured_app_ids, list)
                and app_id in configured_app_ids
            )
    except db.ManagedOAuthCredentialError:
        provider_binding = False
    checks.append(
        _setup_check(
            "credential.providerBinding",
            passed=provider_binding,
            summary="Verified OAuth subject is bound to the same provider and signed policy subject.",
            evidence={
                "provider": provider_id,
                "providerSubjectBound": bool(provider_subject),
            },
        )
    )
    granted_scopes = metadata.get("scopes")
    try:
        stored_scope_set = frozenset(
            _canonical_oauth_granted_scopes(
                granted_scopes,
                field_name="OAuth credential metadata scopes",
            )
        )
        policy_scope_set = frozenset(
            _canonical_oauth_granted_scopes(
                list(policy_credential.scopes),
                field_name="signed policy OAuth scopes",
            )
        )
        scope_binding = stored_scope_set == policy_scope_set
    except OAuthError:
        scope_binding = False
    checks.append(
        _setup_check(
            "credential.scopeBinding",
            passed=scope_binding,
            summary="Stored and signed-policy OAuth scope sets agree exactly and are non-empty.",
            evidence={
                "policyScopeCount": len(policy_credential.scopes),
                "grantedScopeCount": len(granted_scopes)
                if isinstance(granted_scopes, list)
                else 0,
            },
        )
    )
    return checks


def _build_setup_verification(payload: SetupVerificationRequest) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if snapshot is None:
        raise HTTPException(
            status_code=503, detail="active signed policy is unavailable"
        )
    route = next(
        (item for item in snapshot.routes if item.id == payload.route_id), None
    )
    raw_route = next(
        (
            item
            for item in (snapshot.raw.get("routes") or [])
            if isinstance(item, dict) and item.get("id") == payload.route_id
        ),
        None,
    )
    active_route_policy_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                raw_route,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if raw_route is not None
        else None
    )
    credential = db.get_credential(payload.credential_id, include_inactive=True)
    principal_exists = payload.principal_id in snapshot.principals
    route_principal = route is not None and (
        payload.principal_id in route.principals or "*" in route.principals
    )
    checks = [
        _setup_check(
            "policy.active",
            passed=True,
            summary="A signed policy snapshot is active.",
            evidence={"policyHash": snapshot.hash},
        ),
        _setup_check(
            "principal.active",
            passed=principal_exists,
            summary="Principal exists in the active signed policy.",
            evidence={"principalId": payload.principal_id},
        ),
        _setup_check(
            "route.active",
            passed=route is not None,
            summary="Route exists in the active signed policy.",
            evidence={"routeId": payload.route_id},
        ),
        _setup_check(
            "route.principalBinding",
            passed=route_principal,
            summary="Route is assigned to the selected principal.",
        ),
        _setup_check(
            "route.policyBinding",
            passed=(
                active_route_policy_digest is not None
                and active_route_policy_digest == payload.route_policy_digest
            ),
            summary="The active route policy exactly matches the reviewed restriction.",
            evidence={"routePolicyDigest": active_route_policy_digest},
        ),
    ]
    checks.extend(
        _setup_credential_binding_checks(
            snapshot=snapshot,
            route=route,
            credential=credential,
            credential_id=payload.credential_id,
        )
    )

    attestation = attestation_document(payload.nonce)
    assurance = (
        attestation.get("assurance")
        if isinstance(attestation.get("assurance"), dict)
        else {}
    )
    attestation_matches = (
        attestation.get("nonce") == payload.nonce
        and attestation.get("policy_bundle_digest") == snapshot.hash
        and isinstance(attestation.get("runtime_manifest_digest"), str)
        and isinstance(attestation.get("response_signing_key_id"), str)
    )
    checks.append(
        _setup_check(
            "attestation.serverClaims",
            passed=attestation_matches,
            summary="Server claims bind this nonce to the active policy and response key; client verification remains separate.",
            evidence={
                "policyHash": attestation.get("policy_bundle_digest"),
                "runtimeManifestDigest": attestation.get("runtime_manifest_digest"),
                "responseSigningKeyId": attestation.get("response_signing_key_id"),
            },
        )
    )
    hardware_claimed = (
        assurance.get("hardware_proof") is True
        and assurance.get("workload_custody_proven") is True
        and assurance.get("tls_peer_binding_proven") is True
    )
    hardware_verified = False
    checks.append(
        _setup_check(
            "attestation.independentHardwareVerification",
            passed=False,
            required=False,
            summary="Independent client verification of hardware custody is not recorded by this server-side check.",
            evidence={
                "assuranceClass": assurance.get("class"),
                "serverClaimsHardwareAssurance": hardware_claimed,
            },
        )
    )

    required_checks_pass = all(
        item["status"] == "pass" for item in checks if item["required"]
    )
    credential_version = (
        int(credential.get("credential_version") or 0) if credential else 0
    )
    enrollment_evidence = _setup_enrollment_session_evidence(
        payload,
        policy_hash=snapshot.hash,
        credential_version=credential_version,
    )
    checks.append(
        _setup_check(
            "enrollment.caCapabilityConsumed",
            passed=enrollment_evidence is not None,
            required=False,
            summary="The signed enrollment packet's exact one-use CA capability was consumed for this assignment.",
            evidence=enrollment_evidence,
        )
    )
    release_evidence = None
    response_evidence = None
    jit_evidence = None
    authoritative_jit_evidence = None
    if (
        required_checks_pass
        and credential_version > 0
        and enrollment_evidence is not None
    ):
        evidence_start = str(enrollment_evidence["evidenceNotBefore"])
        enrollment_session_id = str(enrollment_evidence["sessionId"])
        release_candidates = _setup_audit_evidence_candidates(
            "data_plane.credential.release_started",
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            policy_hash=snapshot.hash,
            credential_id=payload.credential_id,
            credential_version=credential_version,
            start=evidence_start,
            actor_type="data-plane",
            enrollment_session_id=enrollment_session_id,
        )
        response_candidates = _setup_audit_evidence_candidates(
            "data_plane.response.released",
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            policy_hash=snapshot.hash,
            credential_id=payload.credential_id,
            credential_version=credential_version,
            start=evidence_start,
            actor_type="data-plane",
            enrollment_session_id=enrollment_session_id,
        )
        valid_response_candidates = [
            item
            for item in response_candidates
            if (
                item.get("outcome") == "released"
                and isinstance(item.get("upstreamStatus"), int)
                and 100 <= item["upstreamStatus"] <= 599
                and isinstance(item.get("responseBodySha256"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", item["responseBodySha256"])
                and isinstance(item.get("responseValidation"), dict)
                and all(
                    isinstance(item.get(field), str) and item.get(field)
                    for field in ("requestDigest", "operationDigest", "flowId")
                )
            )
        ]

        def response_for_release(
            candidate_release: dict[str, Any],
        ) -> dict[str, Any] | None:
            release_created_at = _parse_iso_datetime(candidate_release.get("createdAt"))
            for candidate_response in valid_response_candidates:
                if any(
                    candidate_response.get(field) != candidate_release.get(field)
                    for field in ("requestDigest", "operationDigest", "flowId")
                ):
                    continue
                response_created_at = _parse_iso_datetime(
                    candidate_response.get("createdAt")
                )
                if (
                    release_created_at is not None
                    and response_created_at is not None
                    and response_created_at < release_created_at
                ):
                    continue
                return candidate_response
            return None

        for candidate_release in release_candidates:
            if not all(
                isinstance(candidate_release.get(field), str)
                and candidate_release.get(field)
                for field in ("requestDigest", "operationDigest", "flowId")
            ):
                continue
            if release_evidence is None:
                release_evidence = candidate_release
            candidate_response = response_for_release(candidate_release)
            if candidate_response is not None:
                release_evidence = candidate_release
                response_evidence = candidate_response
                break
        if route is not None and route.jit.get("required") is True:
            jit_candidates = _setup_audit_evidence_candidates(
                "data_plane.jit.grant_consumed",
                principal_id=payload.principal_id,
                route_id=payload.route_id,
                policy_hash=snapshot.hash,
                credential_id=payload.credential_id,
                credential_version=credential_version,
                start=evidence_start,
                actor_type="data-plane",
                enrollment_session_id=enrollment_session_id,
            )
            authoritative_jit_candidates = _setup_audit_evidence_candidates(
                "jit.grant.consumed",
                principal_id=payload.principal_id,
                route_id=payload.route_id,
                policy_hash=snapshot.hash,
                credential_id=payload.credential_id,
                credential_version=credential_version,
                start=evidence_start,
                actor_type="proxy",
            )
            authoritative_by_correlation = {
                (
                    item.get("requestDigest"),
                    item.get("operationDigest"),
                    item.get("flowId"),
                    item.get("grantId"),
                    item.get("approvalId"),
                ): item
                for item in authoritative_jit_candidates
                if all(
                    isinstance(item.get(field), str) and item.get(field)
                    for field in (
                        "requestDigest",
                        "operationDigest",
                        "flowId",
                        "grantId",
                        "approvalId",
                    )
                )
            }
            data_plane_by_correlation = {
                (
                    item.get("requestDigest"),
                    item.get("operationDigest"),
                    item.get("flowId"),
                    item.get("grantId"),
                    item.get("approvalId"),
                ): item
                for item in jit_candidates
                if all(
                    isinstance(item.get(field), str) and item.get(field)
                    for field in (
                        "requestDigest",
                        "operationDigest",
                        "flowId",
                        "grantId",
                        "approvalId",
                    )
                )
            }
            release_without_jit = release_evidence
            release_evidence = release_without_jit
            response_evidence = None
            jit_fallback = None
            for candidate_release in release_candidates:
                release_correlation = (
                    candidate_release.get("requestDigest"),
                    candidate_release.get("operationDigest"),
                    candidate_release.get("flowId"),
                    candidate_release.get("grantId"),
                    candidate_release.get("approvalId"),
                )
                if not all(
                    isinstance(value, str) and value for value in release_correlation
                ):
                    continue
                candidate = data_plane_by_correlation.get(release_correlation)
                authoritative_candidate = authoritative_by_correlation.get(
                    release_correlation
                )
                candidate_response = response_for_release(candidate_release)
                if candidate is not None and authoritative_candidate is not None:
                    if jit_fallback is None:
                        jit_fallback = (
                            candidate_release,
                            candidate,
                            authoritative_candidate,
                        )
                    if (
                        candidate_response is None
                        or candidate_response.get("grantId") != release_correlation[3]
                        or candidate_response.get("approvalId")
                        != release_correlation[4]
                    ):
                        continue
                    release_evidence = candidate_release
                    response_evidence = candidate_response
                    jit_evidence = candidate
                    authoritative_jit_evidence = authoritative_candidate
                    break
            if response_evidence is None and jit_fallback is not None:
                release_evidence, jit_evidence, authoritative_jit_evidence = (
                    jit_fallback
                )
    jit_required = route is not None and route.jit.get("required") is True
    checks.extend(
        [
            _setup_check(
                "runtime.credentialRelease",
                passed=release_evidence is not None,
                required=False,
                summary="A durable pre-release audit event proves this exact assignment began an upstream send.",
                evidence=release_evidence,
            ),
            _setup_check(
                "runtime.responseReleased",
                passed=response_evidence is not None,
                required=False,
                summary="A correlated response passed policy validation and was released to the enrolled agent.",
                evidence=response_evidence,
            ),
            _setup_check(
                "runtime.jitConsumption",
                passed=not jit_required or jit_evidence is not None,
                required=False,
                summary=(
                    "Authoritative grant consumption and data-plane evidence agree for this exact request."
                    if jit_required
                    else "This route does not require JIT approval."
                ),
                evidence=(
                    {
                        "dataPlane": jit_evidence,
                        "grantStore": authoritative_jit_evidence,
                    }
                    if jit_evidence is not None
                    and authoritative_jit_evidence is not None
                    else None
                ),
            ),
        ]
    )
    runtime_verified = (
        required_checks_pass
        and enrollment_evidence is not None
        and release_evidence is not None
        and response_evidence is not None
        and (not jit_required or jit_evidence is not None)
    )
    assignment = {
        "principalId": payload.principal_id,
        "routeId": payload.route_id,
        "credentialId": payload.credential_id,
        "credentialVersion": credential_version or None,
        "policyHash": snapshot.hash,
        "routePolicyDigest": active_route_policy_digest,
    }
    assignment_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                assignment, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()
    )
    if not required_checks_pass:
        next_action = "repair_active_assignment"
    elif not enrollment_evidence:
        next_action = "verify_enrollment_and_install_ca"
    elif not release_evidence:
        next_action = "enroll_agent_and_exercise_route"
    elif jit_required and not jit_evidence:
        next_action = "approve_and_retry_exact_request"
    elif not response_evidence:
        next_action = "wait_for_validated_response_evidence"
    elif not hardware_verified:
        next_action = "verify_on_hardware_backed_deployment"
    else:
        next_action = "verified"
    return {
        "apiVersion": "serverware.setupVerification/v1",
        "checkedAt": _now_iso(),
        "assignment": assignment,
        "assignmentDigest": assignment_digest,
        "configurationReady": required_checks_pass,
        "runtimeVerified": runtime_verified,
        "hardwareVerified": hardware_verified,
        "fullyVerified": runtime_verified and hardware_verified,
        "nextAction": next_action,
        "checks": checks,
        "attestation": {
            "nonce": payload.nonce,
            "teePlatform": attestation.get("tee_platform"),
            "assuranceClass": assurance.get("class"),
            "runtimeManifestDigest": attestation.get("runtime_manifest_digest"),
            "sourceTreeDigest": attestation.get("source_tree_digest"),
            "dataPlaneBinaryDigest": attestation.get("data_plane_binary_digest"),
            "responseSigningKeyId": attestation.get("response_signing_key_id"),
            "policyHighWaterDigest": attestation.get("policy_high_water_digest"),
        },
    }


_SETUP_SESSION_READ_ROLES = {
    "admin",
    "attestation_operator",
    "attestation_reviewer",
    "auditor",
    "credential_owner",
    "policy_author",
    "policy_publisher",
}
_SETUP_SESSION_MUTATION_ROLES = {
    "admin",
    "attestation_operator",
    "attestation_reviewer",
    "credential_owner",
    "policy_author",
    "policy_publisher",
}


def _setup_sha256_json(value: Any) -> str:
    return (
        "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    )


def _setup_active_route(
    snapshot: Any, route_id: str
) -> tuple[Any | None, dict[str, Any] | None, str | None]:
    route = next((item for item in snapshot.routes if item.id == route_id), None)
    raw_route = next(
        (
            item
            for item in (snapshot.raw.get("routes") or [])
            if isinstance(item, dict) and item.get("id") == route_id
        ),
        None,
    )
    return (
        route,
        raw_route,
        _setup_sha256_json(raw_route) if raw_route is not None else None,
    )


def _require_authoritative_setup_route_binding(
    *, route_id: str | None, route_policy_digest: str | None
) -> None:
    if route_id is None and route_policy_digest is None:
        return
    if route_id is None or route_policy_digest is None:
        raise HTTPException(
            status_code=409,
            detail="setup route and reviewed route policy digest must be bound together",
        )
    snapshot = get_policy_snapshot()
    if snapshot is None:
        raise HTTPException(
            status_code=503,
            detail="active signed policy is unavailable for setup route verification",
        )
    route, raw_route, active_digest = _setup_active_route(snapshot, route_id)
    if route is None or raw_route is None or active_digest is None:
        raise HTTPException(
            status_code=409,
            detail="the authoritative active setup route is unavailable",
        )
    if not hmac.compare_digest(route_policy_digest, active_digest):
        raise HTTPException(
            status_code=409,
            detail="reviewed route policy does not match the active route",
        )


def _setup_assignment(
    *,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    policy_hash: str,
    route_policy_digest: str,
) -> tuple[dict[str, Any], str]:
    assignment = {
        "principalId": principal_id,
        "routeId": route_id,
        "credentialId": credential_id,
        "credentialVersion": credential_version,
        "policyHash": policy_hash,
        "routePolicyDigest": route_policy_digest,
    }
    return assignment, _setup_sha256_json(assignment)


def _setup_session_public(item: dict[str, Any]) -> dict[str, Any]:
    field_names = {
        "owner_id": "ownerId",
        "current_assignee_id": "currentAssigneeId",
        "template_id": "templateId",
        "principal_id": "principalId",
        "route_id": "routeId",
        "route_policy_digest": "routePolicyDigest",
        "credential_id": "credentialId",
        "credential_version": "credentialVersion",
        "policy_hash": "policyHash",
        "assignment_digest": "assignmentDigest",
        "oauth_provider": "oauthProvider",
        "oauth_state_digest": "oauthStateDigest",
        "oauth_pending_credential_id": "oauthPendingCredentialId",
        "canary_id": "canaryId",
        "enrollment_session_id": "enrollmentSessionId",
        "enrollment_packet_digest": "enrollmentPacketDigest",
        "verifier_nonce_hash": "verifierNonceHash",
        "enrollment_verifier_receipt_digest": "enrollmentVerifierReceiptDigest",
        "enrollment_verifier_key_id": "enrollmentVerifierKeyId",
        "attestation_challenge_digest": "attestationChallengeDigest",
        "attestation_challenge_issued_at": "attestationChallengeIssuedAt",
        "attestation_challenge_expires_at": "attestationChallengeExpiresAt",
        "runtime_evidence_digest": "runtimeEvidenceDigest",
        "hardware_assurance_digest": "hardwareAssuranceDigest",
        "hardware_verification_receipt_digest": "hardwareVerificationReceiptDigest",
        "hardware_verifier_key_id": "hardwareVerifierKeyId",
        "release_identity_digest": "releaseIdentityDigest",
        "current_host_identity_digest": "currentHostIdentityDigest",
        "proxy_server_statement_digest": "proxyServerStatementDigest",
        "trust_profile_digest": "trustProfileDigest",
        "completion_identity_digest": "completionIdentityDigest",
        "final_authority_key_id": "finalAuthorityKeyId",
        "final_consumption_id": "finalConsumptionId",
        "final_receipt_digest": "finalReceiptDigest",
        "created_at": "createdAt",
        "updated_at": "updatedAt",
        "expires_at": "expiresAt",
        "terminal_at": "terminalAt",
    }
    public = {field_names.get(key, key): value for key, value in item.items()}
    public.pop("attestation_challenge_value", None)
    public["apiVersion"] = "serverware.setupSession/v1"
    return public


def _setup_session_error(exc: db.SetupSessionError) -> None:
    if isinstance(exc, db.SetupSessionNotFoundError):
        raise HTTPException(status_code=404, detail="setup session not found") from exc
    if isinstance(exc, db.SetupSessionStaleRevisionError):
        raise HTTPException(
            status_code=409,
            detail={
                "error": "setup_session_stale_revision",
                "setupSessionId": exc.session_id,
                "expectedRevision": exc.expected_revision,
                "currentRevision": exc.current_revision,
            },
        ) from exc
    if isinstance(exc, db.SetupSessionCapacityError):
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


def _drain_setup_session_audit_outbox(*, limit: int = 100) -> dict[str, int]:
    claimed = db.claim_setup_session_audit_outbox(
        worker_id=f"api:{os.getpid()}:{threading.get_ident()}",
        limit=limit,
    )
    audited = 0
    failed = 0
    for item in claimed:
        try:
            result = db.record_audit_event(
                item["audit_event_type"],
                {
                    **item["event"],
                    "setup_event_id": item["id"],
                    "setup_event_sequence": item["sequence"],
                    "setup_event_payload_digest": item["payload_digest"],
                },
                actor_type="admin",
                actor_id=item["actor_id"],
                idempotency_key=item["audit_idempotency_key"],
            )
            if not db.finish_setup_session_audit_outbox(
                item["id"],
                claim_id=str(item["audit_claim_id"]),
                audit_event_hash=result["event_hash"],
            ):
                raise db.SetupSessionError("setup audit outbox claim was lost")
            audited += 1
        except Exception as exc:
            failed += 1
            try:
                db.finish_setup_session_audit_outbox(
                    item["id"],
                    claim_id=str(item["audit_claim_id"]),
                    error=f"{type(exc).__name__}: {exc}",
                )
            except Exception:
                pass
    return {"claimed": len(claimed), "audited": audited, "failed": failed}


def _load_setup_session_for_identity(
    session_id: str,
    identity: AdminIdentity,
    *,
    mutate: bool = False,
    include_evidence: bool = False,
    include_events: bool = False,
) -> dict[str, Any]:
    try:
        item = db.get_setup_session(
            session_id,
            include_evidence=include_evidence,
            include_events=include_events,
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    if item is None:
        raise HTTPException(status_code=404, detail="setup session not found")
    privileged = identity.has_any_role({"admin"}) or (
        not mutate and identity.has_any_role({"auditor"})
    )
    participant = identity.user_id in {item["owner_id"], item["current_assignee_id"]}
    if not privileged and not participant:
        raise HTTPException(
            status_code=403, detail="setup session is assigned to another operator"
        )
    if mutate and not identity.has_any_role(_SETUP_SESSION_MUTATION_ROLES):
        raise HTTPException(
            status_code=403, detail="setup session mutation role is required"
        )
    return item


def _finish_setup_transition(item: dict[str, Any]) -> dict[str, Any]:
    audit = _drain_setup_session_audit_outbox()
    return {"session": _setup_session_public(item), "audit": audit}


def _setup_receipt_profile():
    try:
        return setup_receipt_trust_profile()
    except SetupReceiptTrustConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="setup receipt trust roots are not securely configured",
        ) from exc


def _setup_receipt_failure(exc: ReceiptVerificationError) -> None:
    raise HTTPException(
        status_code=409,
        detail={"error": "setup_receipt_rejected", "reason": exc.code.value},
    ) from exc


def _plain_setup_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_setup_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_setup_json(item) for item in value]
    return value


async def _setup_receipt_envelope(
    request: Request,
    *,
    required_fields: set[str],
    optional_fields: set[str] | None = None,
) -> Mapping[str, Any]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="setup receipt submission requires application/json")
    try:
        envelope = parse_strict_json_object(
            await request.body(), limits=_SETUP_RECEIPT_ENVELOPE_LIMITS
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    optional = optional_fields or set()
    fields = set(envelope)
    if not required_fields.issubset(fields) or fields - required_fields - optional:
        raise HTTPException(
            status_code=400,
            detail="setup receipt envelope fields do not match the endpoint contract",
        )
    return envelope


def _decode_setup_receipt_blob(value: Any, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise HTTPException(status_code=400, detail=f"{label} must be canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} is not valid base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, value) or not 1 <= len(decoded) <= maximum:
        raise HTTPException(status_code=413, detail=f"{label} exceeds its accepted bound")
    return decoded


def _setup_expected_revision(envelope: Mapping[str, Any]) -> int:
    value = envelope.get("expectedRevision")
    if type(value) is not int or value < 0:
        raise HTTPException(status_code=400, detail="expectedRevision must be a non-negative integer")
    return value


def _setup_assignment_from_session(item: Mapping[str, Any]) -> SetupAssignment:
    required = (
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "route_policy_digest",
    )
    if any(item.get(field) is None for field in required):
        raise HTTPException(status_code=409, detail="setup assignment is incomplete")
    try:
        assignment = SetupAssignment(
            principal_id=str(item["principal_id"]),
            route_id=str(item["route_id"]),
            credential_id=str(item["credential_id"]),
            credential_version=int(item["credential_version"]),
            policy_hash=str(item["policy_hash"]),
            route_policy_digest=str(item["route_policy_digest"]),
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    if not hmac.compare_digest(assignment.digest, str(item.get("assignment_digest") or "")):
        raise HTTPException(status_code=409, detail="setup assignment digest is inconsistent")
    return assignment


def _require_setup_current_assignee(item: Mapping[str, Any], identity: AdminIdentity) -> None:
    if not hmac.compare_digest(str(item.get("current_assignee_id") or ""), identity.user_id):
        raise HTTPException(status_code=403, detail="setup attestation action requires the current assignee")


def _setup_receipt_document(
    raw: bytes, *, limits: JsonLimits | None = None
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    try:
        document = (
            parse_strict_json_object(raw, limits=limits)
            if limits is not None
            else parse_strict_json_object(raw)
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    statement = document.get("statement")
    if not isinstance(statement, Mapping):
        raise HTTPException(status_code=409, detail="setup receipt statement is missing")
    return document, statement


def _setup_receipt_uuid(statement: Mapping[str, Any]) -> str:
    value = statement.get("receipt_id")
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise HTTPException(status_code=409, detail="setup receipt ID is invalid") from exc
    if str(parsed) != value:
        raise HTTPException(status_code=409, detail="setup receipt ID is not canonical")
    return str(value)


def _setup_enrollment_is_authoritatively_consumed(item: Mapping[str, Any]) -> None:
    enrollment_session_id = str(item.get("enrollment_session_id") or "")
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        raw = state.get("sessions", {}).get(enrollment_session_id)
        enrollment = dict(raw) if isinstance(raw, dict) else None
    assignment = {
        "route_id": item.get("route_id"),
        "credential_id": item.get("credential_id"),
        "credential_version": item.get("credential_version"),
    }
    if not (
        enrollment
        and enrollment.get("purpose") == "agent-enrollment"
        and enrollment.get("status") == "consumed"
        and enrollment.get("principal_id") == item.get("principal_id")
        and enrollment.get("policy_hash") == item.get("policy_hash")
        and assignment in (enrollment.get("allowed_assignments") or [])
        and enrollment.get("enrollment_packet_sha256") == item.get("enrollment_packet_digest")
    ):
        raise HTTPException(
            status_code=409,
            detail="the exact enrollment CA capability has not been authoritatively consumed",
        )


def _setup_evidence(item: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    matches = [
        evidence
        for evidence in (item.get("evidence") or [])
        if isinstance(evidence, Mapping) and evidence.get("kind") == kind
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("document"), Mapping):
        raise HTTPException(status_code=409, detail=f"setup {kind} evidence is unavailable")
    return matches[0]


def _verified_setup_enrollment(
    item: Mapping[str, Any], profile: Any
) -> VerifiedEnrollmentVerifierReceipt:
    evidence = _setup_evidence(item, "enrollment_verification")
    raw = setup_receipt_canonical_json_bytes(evidence["document"])
    _, statement = _setup_receipt_document(raw)
    issued_at = statement.get("issued_at_unix")
    if type(issued_at) is not int:
        raise HTTPException(status_code=409, detail="stored enrollment receipt time is invalid")
    expected = EnrollmentReceiptExpected(
        receipt_id=_setup_receipt_uuid(statement),
        setup_session_id=str(item["id"]),
        assignment=_setup_assignment_from_session(item),
        enrollment_session_id=str(item["enrollment_session_id"]),
        enrollment_packet_sha256=str(item["enrollment_packet_digest"]),
        verifier_nonce_sha256=str(item["verifier_nonce_hash"]),
        trust_profile_sha256=profile.digest,
    )
    try:
        return verify_enrollment_verifier_receipt(
            raw,
            trust=profile.enrollment_verifier,
            expected=expected,
            clock=FixedClock(issued_at),
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")


def _setup_hardware_assurance_projection(raw: bytes, profile: Any) -> dict[str, Any]:
    document, statement = _setup_receipt_document(
        raw, limits=_SETUP_HARDWARE_ASSURANCE_JSON_LIMITS
    )
    if set(document) != {"apiVersion", "kind", "statement", "signing_key_id", "signature"}:
        raise HTTPException(status_code=409, detail="hardware assurance fields are not closed")
    if document.get("apiVersion") != "serverware.hardwareAssurance/v1" or document.get("kind") != "ServerwareHardwareAssurance":
        raise HTTPException(status_code=409, detail="hardware assurance type is invalid")
    if document.get("signing_key_id") != profile.hardware_verifier.key_id:
        raise HTTPException(status_code=409, detail="hardware assurance signer is not trusted")
    signature = document.get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise HTTPException(status_code=409, detail="hardware assurance signature is invalid")
    signature_bytes = _decode_setup_receipt_blob(
        signature.split(":", 1)[1], label="hardware assurance signature", maximum=64
    )
    if len(signature_bytes) != 64:
        raise HTTPException(status_code=409, detail="hardware assurance signature length is invalid")
    public_key = serialization.load_der_public_key(profile.hardware_verifier.public_key_spki_der)
    if not isinstance(public_key, Ed25519PublicKey):
        raise HTTPException(status_code=503, detail="hardware verifier trust root is invalid")
    try:
        public_key.verify(signature_bytes, setup_receipt_canonical_json_bytes(statement))
    except InvalidSignature as exc:
        raise HTTPException(status_code=409, detail="hardware assurance signature verification failed") from exc
    now = int(time.time())
    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at > now + 30
        or now - issued_at > 900
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > 900
    ):
        raise HTTPException(status_code=409, detail="hardware assurance validity window is invalid")
    challenge = _decode_setup_receipt_blob(
        statement.get("challenge_nonce"), label="hardware assurance challenge", maximum=64
    )
    if len(challenge) < 32:
        raise HTTPException(status_code=409, detail="hardware assurance challenge is too short")
    eif = statement.get("eif")
    build_manifest = eif.get("build_manifest") if isinstance(eif, Mapping) else None
    host = statement.get("current_host_identity")
    release_digest = build_manifest.get("release_identity_sha256") if isinstance(build_manifest, Mapping) else None
    host_digest = host.get("identity_sha256") if isinstance(host, Mapping) else None
    for value, label in (
        (release_digest, "release identity"),
        (host_digest, "current host identity"),
    ):
        if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise HTTPException(status_code=409, detail=f"hardware assurance {label} digest is invalid")
    return {
        "document": document,
        "documentDigest": setup_receipt_sha256_digest(raw),
        "statementDigest": setup_receipt_sha256_digest(setup_receipt_canonical_json_bytes(statement)),
        "challenge": challenge,
        "challengeDigest": setup_receipt_sha256_digest(challenge),
        "releaseIdentityDigest": release_digest,
        "currentHostIdentityDigest": host_digest,
    }


def _verified_setup_hardware(
    item: Mapping[str, Any], profile: Any
) -> VerifiedSetupHardwareVerification:
    evidence = _setup_evidence(item, "hardware_assurance")
    evidence_document = evidence["document"]
    receipt_document = evidence_document.get("verificationReceipt")
    if not isinstance(receipt_document, Mapping):
        raise HTTPException(status_code=409, detail="stored hardware verification receipt is unavailable")
    raw = setup_receipt_canonical_json_bytes(receipt_document)
    for content_field, digest_field, expected_digest in (
        (
            "hardwareAssuranceBase64url",
            "hardwareAssuranceSha256",
            item.get("hardware_assurance_digest"),
        ),
        (
            "proxyServerStatementBase64url",
            "proxyServerStatementSha256",
            item.get("proxy_server_statement_digest"),
        ),
    ):
        content = _decode_setup_receipt_blob(
            evidence_document.get(content_field),
            label=f"stored {content_field}",
            maximum=_SETUP_HARDWARE_ASSURANCE_MAX_BYTES,
        )
        if not (
            evidence_document.get(digest_field) == expected_digest
            and hmac.compare_digest(
                setup_receipt_sha256_digest(content), str(expected_digest or "")
            )
        ):
            raise HTTPException(status_code=409, detail="stored hardware artifact binding is inconsistent")
    _, statement = _setup_receipt_document(raw)
    issued_at = statement.get("issued_at_unix")
    challenge_text = statement.get("challenge")
    if type(issued_at) is not int:
        raise HTTPException(status_code=409, detail="stored hardware receipt time is invalid")
    challenge = _decode_setup_receipt_blob(
        challenge_text, label="stored hardware challenge", maximum=64
    )
    if not hmac.compare_digest(
        setup_receipt_sha256_digest(challenge),
        str(item.get("attestation_challenge_digest") or ""),
    ):
        raise HTTPException(status_code=409, detail="stored hardware challenge binding is inconsistent")
    expected = HardwareVerificationExpected(
        receipt_id=_setup_receipt_uuid(statement),
        setup_session_id=str(item["id"]),
        assignment=_setup_assignment_from_session(item),
        runtime_evidence_sha256=str(item["runtime_evidence_digest"]),
        challenge=challenge,
        hardware_assurance_sha256=str(item["hardware_assurance_digest"]),
        hardware_statement_sha256=str(statement.get("hardware_statement_sha256") or ""),
        release_identity_sha256=str(item["release_identity_digest"]),
        current_host_identity_sha256=str(item["current_host_identity_digest"]),
        proxy_server_statement_sha256=str(item["proxy_server_statement_digest"]),
        trust_profile_sha256=str(item["trust_profile_digest"]),
    )
    try:
        return verify_setup_hardware_verification(
            raw,
            trust=profile.hardware_verifier,
            expected=expected,
            clock=FixedClock(issued_at),
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")


def _setup_final_receipt_audited(item: Mapping[str, Any]) -> bool:
    return any(
        event.get("transition") == "record_final_challenge_receipt"
        and event.get("audit_status") == "audited"
        and event.get("audited_at")
        and event.get("audit_event_hash")
        for event in (item.get("events") or [])
        if isinstance(event, Mapping)
    )


@app.post("/api/setup/sessions")
def setup_session_create(
    payload: SetupSessionCreateRequest,
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "policy_publisher", "credential_owner")
    ),
) -> dict[str, Any]:
    route_policy_digest = payload.route_policy_digest
    _require_authoritative_setup_route_binding(
        route_id=payload.route_id,
        route_policy_digest=route_policy_digest,
    )
    try:
        item = db.create_setup_session(
            owner_id=identity.user_id,
            current_assignee_id=identity.user_id,
            template_id=payload.template_id,
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            route_policy_digest=route_policy_digest,
            ttl_seconds=payload.ttl_seconds,
            actor_id=identity.user_id,
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(item)


@app.get("/api/setup/sessions")
def setup_sessions(
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    identity: AdminIdentity = Depends(require_role(*sorted(_SETUP_SESSION_READ_ROLES))),
) -> dict[str, Any]:
    _drain_setup_session_audit_outbox()
    try:
        if identity.has_any_role({"admin", "auditor"}):
            items = db.list_setup_sessions(status=status, limit=limit)
        else:
            owned = db.list_setup_sessions(
                owner_id=identity.user_id, status=status, limit=limit
            )
            assigned = db.list_setup_sessions(
                current_assignee_id=identity.user_id, status=status, limit=limit
            )
            by_id = {item["id"]: item for item in [*owned, *assigned]}
            items = sorted(
                by_id.values(),
                key=lambda item: (item["updated_at"], item["id"]),
                reverse=True,
            )[:limit]
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return {"sessions": [_setup_session_public(item) for item in items]}


@app.get("/api/setup/sessions/{session_id}")
def setup_session_get(
    session_id: str,
    identity: AdminIdentity = Depends(require_role(*sorted(_SETUP_SESSION_READ_ROLES))),
) -> dict[str, Any]:
    _drain_setup_session_audit_outbox()
    item = _load_setup_session_for_identity(
        session_id,
        identity,
        include_evidence=True,
        include_events=True,
    )
    return {"session": _setup_session_public(item)}


@app.get("/api/setup/receipt-trust")
def setup_receipt_trust(
    _: AdminIdentity = Depends(require_role(*sorted(_SETUP_SESSION_READ_ROLES))),
) -> dict[str, Any]:
    profile = _setup_receipt_profile()
    return {
        "apiVersion": "serverware.setupReceiptTrustProfile/v1",
        "digest": profile.digest,
        "enrollmentVerifier": {
            "provider": profile.enrollment_verifier.provider,
            "keyId": profile.enrollment_verifier.key_id,
        },
        "hardwareVerifier": {
            "provider": profile.hardware_verifier.provider,
            "keyId": profile.hardware_verifier.key_id,
        },
        "finalAuthority": {
            "provider": profile.final_authority.provider,
            "keyId": profile.final_authority.key_id,
        },
    }


@app.post("/api/setup/sessions/{session_id}/enrollment-receipt")
async def setup_session_enrollment_receipt(
    session_id: str,
    request: Request,
    identity: AdminIdentity = Depends(require_role("attestation_operator")),
) -> dict[str, Any]:
    envelope = await _setup_receipt_envelope(
        request, required_fields={"expectedRevision", "receipt"}
    )
    item = _load_setup_session_for_identity(
        session_id, identity, mutate=True, include_evidence=True
    )
    _require_setup_current_assignee(item, identity)
    expected_revision = _setup_expected_revision(envelope)
    if expected_revision != item["revision"]:
        _setup_session_error(
            db.SetupSessionStaleRevisionError(
                session_id, expected_revision, int(item["revision"])
            )
        )
    if item["phase"] != "enrollment_issued":
        raise HTTPException(status_code=409, detail="setup is not awaiting an enrollment receipt")
    _setup_enrollment_is_authoritatively_consumed(item)
    profile = _setup_receipt_profile()
    raw_receipt = _decode_setup_receipt_blob(
        envelope.get("receipt"), label="enrollment receipt", maximum=_SETUP_RECEIPT_MAX_BYTES
    )
    document, statement = _setup_receipt_document(raw_receipt)
    expected = EnrollmentReceiptExpected(
        receipt_id=_setup_receipt_uuid(statement),
        setup_session_id=session_id,
        assignment=_setup_assignment_from_session(item),
        enrollment_session_id=str(item["enrollment_session_id"]),
        enrollment_packet_sha256=str(item["enrollment_packet_digest"]),
        verifier_nonce_sha256=str(item["verifier_nonce_hash"]),
        trust_profile_sha256=profile.digest,
    )
    try:
        verified = verify_enrollment_verifier_receipt(
            raw_receipt,
            trust=profile.enrollment_verifier,
            expected=expected,
            clock=lambda: int(time.time()),
        )
        updated = db.transition_setup_session(
            session_id,
            expected_revision=expected_revision,
            transition="record_enrollment_evidence",
            actor_id=identity.user_id,
            evidence=[
                {
                    "kind": "enrollment_verification",
                    "document": _plain_setup_json(document),
                    "verifier_key_id": verified.verifier_key_id,
                    "observed_at": datetime.fromtimestamp(
                        verified.issued_at_unix, timezone.utc
                    ).isoformat(),
                }
            ],
            event={
                "receipt_id": verified.receipt_id,
                "receipt_digest": verified.receipt_sha256,
                "trust_profile_digest": verified.trust_profile_sha256,
            },
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/attestation-challenge")
def setup_session_attestation_challenge(
    session_id: str,
    payload: SetupSessionRevisionRequest,
    identity: AdminIdentity = Depends(require_role("attestation_operator")),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    _require_setup_current_assignee(item, identity)
    if item["phase"] != "runtime_verified":
        raise HTTPException(status_code=409, detail="setup runtime evidence is not verified")
    profile = _setup_receipt_profile()
    if payload.expected_revision != item["revision"]:
        _setup_session_error(
            db.SetupSessionStaleRevisionError(
                session_id, payload.expected_revision, int(item["revision"])
            )
        )
    existing_expires = item.get("attestation_challenge_expires_at")
    existing_value = item.get("attestation_challenge_value")
    if existing_expires and existing_value:
        expires = datetime.fromisoformat(str(existing_expires))
        if datetime.now(timezone.utc) < expires:
            challenge = _decode_setup_receipt_blob(
                existing_value,
                label="stored setup challenge",
                maximum=64,
            )
            return {
                "session": _setup_session_public(item),
                "audit": {"claimed": 0, "audited": 0, "failed": 0},
                "challenge": {
                    "apiVersion": "serverware.setupAttestationChallenge/v1",
                    "value": existing_value,
                    "sha256": setup_receipt_sha256_digest(challenge),
                    "expiresAt": expires.isoformat(),
                    "trustProfileDigest": profile.digest,
                },
            }
    challenge = secrets.token_bytes(32)
    challenge_value = base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("=")
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=SETUP_ATTESTATION_CHALLENGE_TTL_SECONDS)
    try:
        updated = db.transition_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            transition="bind_attestation_challenge",
            actor_id=identity.user_id,
            updates={
                "attestation_challenge_digest": setup_receipt_sha256_digest(challenge),
                "attestation_challenge_issued_at": now.isoformat(),
                "attestation_challenge_expires_at": expires.isoformat(),
                "attestation_challenge_value": challenge_value,
            },
            event={"trust_profile_digest": profile.digest},
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    response = _finish_setup_transition(updated)
    response["challenge"] = {
        "apiVersion": "serverware.setupAttestationChallenge/v1",
        "value": challenge_value,
        "sha256": setup_receipt_sha256_digest(challenge),
        "expiresAt": expires.isoformat(),
        "trustProfileDigest": profile.digest,
    }
    return response


@app.post("/api/setup/sessions/{session_id}/hardware-verification")
async def setup_session_hardware_verification(
    session_id: str,
    request: Request,
    identity: AdminIdentity = Depends(require_role("attestation_operator")),
) -> dict[str, Any]:
    envelope = await _setup_receipt_envelope(
        request,
        required_fields={
            "expectedRevision",
            "hardwareAssurance",
            "proxyServerStatement",
            "receipt",
        },
    )
    item = _load_setup_session_for_identity(
        session_id, identity, mutate=True, include_evidence=True
    )
    _require_setup_current_assignee(item, identity)
    expected_revision = _setup_expected_revision(envelope)
    if expected_revision != item["revision"]:
        _setup_session_error(
            db.SetupSessionStaleRevisionError(
                session_id, expected_revision, int(item["revision"])
            )
        )
    if item["phase"] != "runtime_verified" or not item.get("runtime_evidence_digest"):
        raise HTTPException(status_code=409, detail="setup runtime evidence is not verified")
    if not item.get("attestation_challenge_digest"):
        raise HTTPException(status_code=409, detail="setup attestation challenge is unavailable")
    profile = _setup_receipt_profile()
    raw_assurance = _decode_setup_receipt_blob(
        envelope.get("hardwareAssurance"),
        label="hardware assurance",
        maximum=_SETUP_HARDWARE_ASSURANCE_MAX_BYTES,
    )
    assurance = _setup_hardware_assurance_projection(raw_assurance, profile)
    if not hmac.compare_digest(
        assurance["challengeDigest"], str(item["attestation_challenge_digest"])
    ):
        raise HTTPException(status_code=409, detail="hardware assurance challenge does not match this setup")
    raw_proxy_statement = _decode_setup_receipt_blob(
        envelope.get("proxyServerStatement"),
        label="proxy server statement",
        maximum=128 * 1024,
    )
    proxy_statement_digest = setup_receipt_sha256_digest(raw_proxy_statement)
    raw_receipt = _decode_setup_receipt_blob(
        envelope.get("receipt"),
        label="hardware verification receipt",
        maximum=_SETUP_RECEIPT_MAX_BYTES,
    )
    document, statement = _setup_receipt_document(raw_receipt)
    expected = HardwareVerificationExpected(
        receipt_id=_setup_receipt_uuid(statement),
        setup_session_id=session_id,
        assignment=_setup_assignment_from_session(item),
        runtime_evidence_sha256=str(item["runtime_evidence_digest"]),
        challenge=assurance["challenge"],
        hardware_assurance_sha256=assurance["documentDigest"],
        hardware_statement_sha256=assurance["statementDigest"],
        release_identity_sha256=assurance["releaseIdentityDigest"],
        current_host_identity_sha256=assurance["currentHostIdentityDigest"],
        proxy_server_statement_sha256=proxy_statement_digest,
        trust_profile_sha256=profile.digest,
    )
    try:
        verified = verify_setup_hardware_verification(
            raw_receipt,
            trust=profile.hardware_verifier,
            expected=expected,
            clock=lambda: int(time.time()),
        )
        completion = derive_setup_completion_identity(
            _verified_setup_enrollment(item, profile), verified
        )
        updated = db.transition_setup_session(
            session_id,
            expected_revision=expected_revision,
            transition="record_hardware_receipt",
            actor_id=identity.user_id,
            updates={
                "hardware_assurance_digest": verified.hardware_assurance_sha256,
                "hardware_verification_receipt_digest": verified.receipt_sha256,
                "release_identity_digest": verified.release_identity_sha256,
                "current_host_identity_digest": verified.current_host_identity_sha256,
                "proxy_server_statement_digest": verified.proxy_server_statement_sha256,
                "trust_profile_digest": verified.trust_profile_sha256,
            },
            evidence=[
                {
                    "kind": "hardware_assurance",
                    "document": {
                        "apiVersion": "serverware.setupHardwareEvidence/v1",
                        "hardwareAssuranceBase64url": base64.urlsafe_b64encode(
                            raw_assurance
                        ).decode("ascii").rstrip("="),
                        "hardwareAssuranceSha256": verified.hardware_assurance_sha256,
                        "proxyServerStatementBase64url": base64.urlsafe_b64encode(
                            raw_proxy_statement
                        ).decode("ascii").rstrip("="),
                        "proxyServerStatementSha256": verified.proxy_server_statement_sha256,
                        "verificationReceipt": _plain_setup_json(document),
                    },
                    "verifier_key_id": verified.hardware_verifier_key_id,
                    "observed_at": datetime.fromtimestamp(
                        verified.issued_at_unix, timezone.utc
                    ).isoformat(),
                }
            ],
            event={
                "receipt_id": verified.receipt_id,
                "receipt_digest": verified.receipt_sha256,
                "hardware_assurance_digest": verified.hardware_assurance_sha256,
                "hardware_statement_digest": verified.hardware_statement_sha256,
                "completion_identity_digest": completion.digest_sha256,
            },
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    response = _finish_setup_transition(updated)
    response["completionIdentity"] = {
        "apiVersion": "serverware.setupCompletionIdentity/v1",
        "sha256": completion.digest_sha256,
        "document": _plain_setup_json(completion.document),
    }
    return response


@app.post("/api/setup/sessions/{session_id}/final-receipt")
async def setup_session_final_receipt(
    session_id: str,
    request: Request,
    identity: AdminIdentity = Depends(require_role("attestation_reviewer")),
) -> dict[str, Any]:
    envelope = await _setup_receipt_envelope(
        request,
        required_fields={"expectedRevision", "receipt"},
        optional_fields={"mfa"},
    )
    item = _load_setup_session_for_identity(
        session_id,
        identity,
        mutate=True,
        include_evidence=True,
        include_events=True,
    )
    _require_setup_current_assignee(item, identity)
    expected_revision = _setup_expected_revision(envelope)
    if expected_revision != item["revision"]:
        _setup_session_error(
            db.SetupSessionStaleRevisionError(
                session_id, expected_revision, int(item["revision"])
            )
        )
    if item["phase"] not in {"hardware_verified", "completion_pending_audit", "complete"}:
        raise HTTPException(status_code=409, detail="setup hardware evidence is not verified")
    profile = _setup_receipt_profile()
    completion = derive_setup_completion_identity(
        _verified_setup_enrollment(item, profile),
        _verified_setup_hardware(item, profile),
    )
    raw_receipt = _decode_setup_receipt_blob(
        envelope.get("receipt"),
        label="final challenge receipt",
        maximum=_SETUP_RECEIPT_MAX_BYTES,
    )
    document, statement = _setup_receipt_document(raw_receipt)
    receipt_clock = FixedClock(int(time.time()))
    if item["phase"] in {"completion_pending_audit", "complete"}:
        issued_at = statement.get("issued_at_unix")
        if type(issued_at) is not int:
            raise HTTPException(status_code=409, detail="final receipt time is invalid")
        receipt_clock = FixedClock(issued_at)
    try:
        verified = verify_final_challenge_receipt(
            raw_receipt,
            trust=profile.final_challenge_trust,
            completion=completion,
            clock=receipt_clock,
        )
    except ReceiptVerificationError as exc:
        _setup_receipt_failure(exc)
        raise AssertionError("unreachable")
    if item["phase"] in {"completion_pending_audit", "complete"}:
        if not (
            hmac.compare_digest(verified.receipt_sha256, str(item.get("final_receipt_digest") or ""))
            and hmac.compare_digest(verified.consumption_id, str(item.get("final_consumption_id") or ""))
            and hmac.compare_digest(completion.digest_sha256, str(item.get("completion_identity_digest") or ""))
        ):
            raise HTTPException(status_code=409, detail="final receipt retry does not match the accepted receipt")
    if item["phase"] == "hardware_verified":
        raw_mfa = envelope.get("mfa")
        if raw_mfa is not None and not isinstance(raw_mfa, Mapping):
            raise HTTPException(status_code=400, detail="final receipt mfa must be an object")
        mfa = _plain_setup_json(raw_mfa) if raw_mfa is not None else None
        payload_digest = _control_plane_payload_digest(
            {
                "setup_session_id": session_id,
                "expected_revision": expected_revision,
                "final_receipt_digest": verified.receipt_sha256,
                "completion_identity_digest": completion.digest_sha256,
            }
        )
        verified_mfa = _require_control_plane_mutation_mfa(
            action="setup.attestation.finalize",
            resource_id=session_id,
            payload_digest=payload_digest,
            mfa=mfa,
            identity=identity,
        )
        approval_request = {
            "setup_session_id": session_id,
            "final_receipt_digest": verified.receipt_sha256,
            "completion_identity_digest": completion.digest_sha256,
        }

        def accept_final_receipt(
            two_person: dict[str, Any] | None,
            *,
            connection: Any | None = None,
        ) -> dict[str, Any]:
            return db.transition_setup_session(
                session_id,
                expected_revision=expected_revision,
                transition="record_final_challenge_receipt",
                actor_id=identity.user_id,
                updates={
                    "completion_identity_digest": completion.digest_sha256,
                    "final_consumption_id": verified.consumption_id,
                },
                evidence=[
                    {
                        "kind": "final_challenge_receipt",
                        "document": _plain_setup_json(document),
                        "verifier_key_id": verified.authority_key_id,
                        "observed_at": datetime.fromtimestamp(
                            verified.issued_at_unix, timezone.utc
                        ).isoformat(),
                    }
                ],
                event={
                    "receipt_digest": verified.receipt_sha256,
                    "consumption_id": verified.consumption_id,
                    "completion_identity_digest": completion.digest_sha256,
                    "control_plane_mfa": verified_mfa,
                    "control_plane_approval": two_person,
                    "payload_digest": payload_digest,
                },
                _connection=connection,
            )

        try:
            if _control_plane_two_person_required("setup.attestation.finalize") and _control_plane_approval_id(mfa):
                with db.connect() as connection:
                    two_person = _require_control_plane_two_person(
                        action="setup.attestation.finalize",
                        resource_id=session_id,
                        payload_digest=payload_digest,
                        mfa=mfa,
                        identity=identity,
                        request=approval_request,
                        connection=connection,
                    )
                    item = accept_final_receipt(
                        two_person, connection=connection
                    )
            else:
                two_person = _require_control_plane_two_person(
                    action="setup.attestation.finalize",
                    resource_id=session_id,
                    payload_digest=payload_digest,
                    mfa=mfa,
                    identity=identity,
                    request=approval_request,
                )
                item = accept_final_receipt(two_person)
        except db.SetupSessionError as exc:
            _setup_session_error(exc)
            raise AssertionError("unreachable")
    audit = _drain_setup_session_audit_outbox()
    item = _load_setup_session_for_identity(
        session_id,
        identity,
        mutate=True,
        include_evidence=True,
        include_events=True,
    )
    if item["phase"] == "completion_pending_audit" and _setup_final_receipt_audited(item):
        try:
            item = db.transition_setup_session(
                session_id,
                expected_revision=int(item["revision"]),
                transition="system_complete",
                actor_id="serverware:setup-audit-finalizer",
                event={
                    "final_receipt_digest": verified.receipt_sha256,
                    "completion_identity_digest": completion.digest_sha256,
                },
            )
        except db.SetupSessionError as exc:
            _setup_session_error(exc)
            raise AssertionError("unreachable")
        completion_audit = _drain_setup_session_audit_outbox()
        audit = {
            key: audit.get(key, 0) + completion_audit.get(key, 0)
            for key in {"claimed", "audited", "failed"}
        }
    return {
        "session": _setup_session_public(item),
        "audit": audit,
        "completionIdentity": {
            "apiVersion": "serverware.setupCompletionIdentity/v1",
            "sha256": completion.digest_sha256,
            "document": _plain_setup_json(completion.document),
        },
        "finalReceipt": {
            "sha256": verified.receipt_sha256,
            "consumptionId": verified.consumption_id,
            "authorityKeyId": verified.authority_key_id,
        },
    }


@app.post("/api/setup/sessions/{session_id}/claim")
def setup_session_claim(
    session_id: str,
    payload: SetupSessionRevisionRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    try:
        updated = db.claim_or_handoff_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            actor_id=identity.user_id,
            assignee_id=identity.user_id,
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    assert item
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/handoff")
def setup_session_handoff(
    session_id: str,
    payload: SetupSessionHandoffRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    if identity.user_id != item["owner_id"] and not identity.has_any_role({"admin"}):
        raise HTTPException(
            status_code=403,
            detail="only the setup owner or an admin can hand off this session",
        )
    try:
        updated = db.claim_or_handoff_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            actor_id=identity.user_id,
            assignee_id=payload.assignee_id,
            handoff=True,
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/cancel")
def setup_session_cancel(
    session_id: str,
    payload: SetupSessionCancelRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    _load_setup_session_for_identity(session_id, identity, mutate=True)
    try:
        updated = db.cancel_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            actor_id=identity.user_id,
            reason=payload.reason,
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/credential")
def setup_session_bind_credential(
    session_id: str,
    payload: SetupSessionCredentialRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    credential = db.get_credential(payload.credential_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="active credential not found")
    version = int(credential.get("credential_version") or 0)
    if version < 1:
        raise HTTPException(
            status_code=409, detail="credential generation is unavailable"
        )
    try:
        updated = db.transition_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            transition="bind_credential",
            actor_id=identity.user_id,
            updates={
                "credential_id": payload.credential_id,
                "credential_version": version,
                **(
                    {"route_policy_digest": item["route_policy_digest"]}
                    if item.get("route_policy_digest") is not None
                    else {}
                ),
            },
            event={
                "credential_lifecycle_status": credential.get(
                    "lifecycle_status", "active"
                )
            },
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/canary")
def setup_session_bind_canary(
    session_id: str,
    payload: SetupSessionCanaryRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    state = _read_policy_canary_state()
    if not state or state.get("id") != payload.canary_id:
        raise HTTPException(status_code=404, detail="policy canary not found")
    if state.get("status") not in {"running", "activated"}:
        raise HTTPException(status_code=409, detail="policy canary is not usable")
    signed_bundle = state.get("signed_bundle")
    if not isinstance(signed_bundle, dict):
        raise HTTPException(
            status_code=503, detail="policy canary signed bundle is missing"
        )
    try:
        candidate = compile_policy_bundle(
            signed_bundle, verify_signature=True, validate_schema=True
        )
    except PolicyBundleError as exc:
        raise HTTPException(
            status_code=409, detail=f"policy canary bundle is invalid: {exc}"
        ) from exc
    if candidate.hash != state.get("candidate_policy_hash"):
        raise HTTPException(
            status_code=409,
            detail="policy canary hash does not match its signed bundle",
        )
    route, raw_route, route_digest = _setup_active_route(
        candidate, str(item.get("route_id") or "")
    )
    if route is None or raw_route is None or route_digest is None:
        raise HTTPException(
            status_code=409, detail="candidate does not contain the setup route"
        )
    if item.get("principal_id") not in route.principals and "*" not in route.principals:
        raise HTTPException(
            status_code=409,
            detail="candidate route is not assigned to the setup principal",
        )
    if route.credential_ref != item.get("credential_id"):
        raise HTTPException(
            status_code=409, detail="candidate route does not use the setup credential"
        )
    assignment, assignment_digest = _setup_assignment(
        principal_id=str(item["principal_id"]),
        route_id=str(item["route_id"]),
        credential_id=str(item["credential_id"]),
        credential_version=int(item["credential_version"]),
        policy_hash=candidate.hash,
        route_policy_digest=route_digest,
    )
    try:
        updated = db.transition_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            transition="bind_candidate",
            actor_id=identity.user_id,
            updates={
                "canary_id": payload.canary_id,
                "policy_hash": candidate.hash,
                "route_policy_digest": route_digest,
                "assignment_digest": assignment_digest,
            },
            event={"assignment": assignment, "canary_status": state.get("status")},
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/policy")
def setup_session_bind_active_policy(
    session_id: str,
    payload: SetupSessionRevisionRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    snapshot = get_policy_snapshot()
    if snapshot is None or snapshot.hash != item.get("policy_hash"):
        raise HTTPException(
            status_code=409,
            detail="the setup candidate is not the active signed policy",
        )
    route, _, route_digest = _setup_active_route(
        snapshot, str(item.get("route_id") or "")
    )
    if route is None or route_digest != item.get("route_policy_digest"):
        raise HTTPException(
            status_code=409,
            detail="the active route differs from the reviewed setup route",
        )
    if route.credential_ref != item.get("credential_id"):
        raise HTTPException(
            status_code=409, detail="the active route uses a different credential"
        )
    assignment, assignment_digest = _setup_assignment(
        principal_id=str(item["principal_id"]),
        route_id=str(item["route_id"]),
        credential_id=str(item["credential_id"]),
        credential_version=int(item["credential_version"]),
        policy_hash=snapshot.hash,
        route_policy_digest=str(route_digest),
    )
    if assignment_digest != item.get("assignment_digest"):
        raise HTTPException(
            status_code=409,
            detail="the active assignment differs from the staged setup assignment",
        )
    try:
        updated = db.transition_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            transition="activate_policy",
            actor_id=identity.user_id,
            updates={
                "policy_hash": snapshot.hash,
                "assignment_digest": assignment_digest,
            },
            event={"assignment": assignment},
            required_active_credential_id=str(item["credential_id"]),
            required_active_credential_version=int(item["credential_version"]),
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/enrollment")
def setup_session_bind_enrollment(
    session_id: str,
    payload: SetupSessionEnrollmentRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    with _ca_install_sessions_lock():
        state = _read_ca_install_sessions()
        raw = state.get("sessions", {}).get(payload.enrollment_session_id)
        enrollment = dict(raw) if isinstance(raw, dict) else None
    if enrollment is None:
        raise HTTPException(
            status_code=404, detail="agent enrollment session not found"
        )
    assignment = {
        "route_id": item.get("route_id"),
        "credential_id": item.get("credential_id"),
        "credential_version": item.get("credential_version"),
    }
    if not (
        enrollment.get("purpose") == "agent-enrollment"
        and enrollment.get("status") in {"active", "claimed", "consumed"}
        and enrollment.get("principal_id") == item.get("principal_id")
        and enrollment.get("policy_hash") == item.get("policy_hash")
        and assignment in (enrollment.get("allowed_assignments") or [])
        and isinstance(enrollment.get("enrollment_packet_sha256"), str)
        and hmac.compare_digest(
            str(enrollment.get("nonce") or ""), payload.verifier_nonce
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="enrollment session does not match the exact setup assignment",
        )
    nonce_hash = (
        "sha256:" + hashlib.sha256(payload.verifier_nonce.encode("ascii")).hexdigest()
    )
    try:
        updated = db.transition_setup_session(
            session_id,
            expected_revision=payload.expected_revision,
            transition="bind_enrollment",
            actor_id=identity.user_id,
            updates={
                "enrollment_session_id": payload.enrollment_session_id,
                "enrollment_packet_digest": enrollment["enrollment_packet_sha256"],
                "verifier_nonce_hash": nonce_hash,
            },
            event={"enrollment_status": enrollment.get("status")},
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    return _finish_setup_transition(updated)


@app.post("/api/setup/sessions/{session_id}/verify")
def setup_session_verify(
    session_id: str,
    payload: SetupSessionVerifyRequest,
    identity: AdminIdentity = Depends(
        require_role(*sorted(_SETUP_SESSION_MUTATION_ROLES))
    ),
) -> dict[str, Any]:
    item = _load_setup_session_for_identity(session_id, identity, mutate=True)
    if payload.expected_revision != item["revision"]:
        _setup_session_error(
            db.SetupSessionStaleRevisionError(
                session_id, payload.expected_revision, item["revision"]
            )
        )
    required = (
        "principal_id",
        "route_id",
        "credential_id",
        "route_policy_digest",
        "enrollment_session_id",
    )
    if any(item.get(field) is None for field in required):
        raise HTTPException(
            status_code=409,
            detail="setup session does not have a complete active assignment",
        )
    result = _build_setup_verification(
        SetupVerificationRequest(
            principalId=item["principal_id"],
            routeId=item["route_id"],
            credentialId=item["credential_id"],
            routePolicyDigest=item["route_policy_digest"],
            nonce=payload.nonce,
            enrollmentSessionId=item["enrollment_session_id"],
        )
    )
    current = item
    try:
        if current["phase"] == "ca_installed":
            canary = _read_policy_canary_state()
            if (
                canary
                and canary.get("id") == current.get("canary_id")
                and canary.get("status") == "activated"
                and canary.get("candidate_policy_hash") == current.get("policy_hash")
            ):
                monitoring = canary.get("activation_monitoring")
                if not isinstance(monitoring, dict):
                    monitoring = _policy_canary_monitor(canary)
                if monitoring.get("complete") is True:
                    current = db.transition_setup_session(
                        session_id,
                        expected_revision=current["revision"],
                        transition="record_canary_evidence",
                        actor_id=identity.user_id,
                        evidence=[
                            {
                                "kind": "canary_result",
                                "document": {
                                    "canaryId": current["canary_id"],
                                    "policyHash": current["policy_hash"],
                                    "monitoring": monitoring,
                                },
                                "verifier_key_id": "serverware-audit-chain",
                                "observed_at": result["checkedAt"],
                            }
                        ],
                    )
        if (
            current["phase"] == "canaries_verified"
            and result["runtimeVerified"] is True
        ):
            current = db.transition_setup_session(
                session_id,
                expected_revision=current["revision"],
                transition="record_runtime_evidence",
                actor_id=identity.user_id,
                evidence=[
                    {
                        "kind": "runtime_verification",
                        "document": {
                            "assignment": result["assignment"],
                            "assignmentDigest": result["assignmentDigest"],
                            "configurationReady": result["configurationReady"],
                            "runtimeVerified": result["runtimeVerified"],
                        },
                        "verifier_key_id": "serverware-audit-chain",
                        "observed_at": result["checkedAt"],
                    }
                ],
            )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
        raise AssertionError("unreachable")
    response = _finish_setup_transition(current)
    result["setupSessionId"] = current["id"]
    result["setupRevision"] = current["revision"]
    response["verification"] = result
    return response


@app.post("/api/setup/verify")
def setup_verification(
    payload: SetupVerificationRequest,
    identity: AdminIdentity = Depends(
        require_role("policy_author", "policy_publisher", "credential_owner", "auditor")
    ),
) -> dict[str, Any]:
    result = _build_setup_verification(payload)
    db.record_audit_event(
        "setup.verification.checked",
        {
            "assignment": result["assignment"],
            "assignment_digest": result["assignmentDigest"],
            "configuration_ready": result["configurationReady"],
            "runtime_verified": result["runtimeVerified"],
            "hardware_verified": result["hardwareVerified"],
            "next_action": result["nextAction"],
        },
        actor_id=identity.user_id,
    )
    return result


@app.post("/api/agents/enrollment")
def agent_enrollment(
    payload: AgentEnrollmentCreate,
    identity: AdminIdentity = Depends(require_role("policy_author")),
) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    if snapshot is None:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    try:
        configured_control_plane_url = canonical_control_plane_url(PUBLIC_URL)
        if (
            payload.control_plane_url is not None
            and canonical_control_plane_url(payload.control_plane_url)
            != configured_control_plane_url
        ):
            raise AgentEnrollmentError(
                "control plane URL must match configured SERVERWARE_PUBLIC_URL"
            )
        attestation = attestation_document(payload.nonce)
        enrollment_args = {
            "snapshot": snapshot,
            "principal_id": payload.principal_id,
            "attestation": attestation,
            "proxy_url": payload.proxy_url,
            "control_plane_url": configured_control_plane_url,
            "proxy_egress_cidrs": payload.proxy_egress_cidrs,
            "namespace": payload.namespace,
            "pod_selector": payload.pod_selector,
            "ca_mount_path": payload.ca_mount_path,
            "nonce": payload.nonce,
            "ttl_seconds": payload.ttl_seconds,
        }
        # Validate every enrollment field before allocating the one-use capability.
        build_agent_enrollment(**enrollment_args)
        session, token = _create_ca_install_session(
            created_by=identity.user_id,
            nonce=payload.nonce,
            ttl_seconds=payload.ttl_seconds,
            policy_hash=snapshot.hash,
            principal_id=payload.principal_id,
            purpose="agent-enrollment",
        )
        session_public = _ca_install_session_public(session, include_token=token)
        install_session = {
            field: session_public[field]
            for field in (
                "id",
                "nonce",
                "token",
                "tokenHeader",
                "policyUrl",
                "downloadUrl",
                "expiresAt",
            )
        }
        packet = build_agent_enrollment(
            **enrollment_args,
            ca_install_session=install_session,
        )
        _bind_enrollment_session_packet(str(session["id"]), packet)
        return packet
    except AgentEnrollmentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/oauth/providers")
def oauth_providers(
    _: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
    return {"providers": provider_status()}


def _canonical_oauth_granted_scopes(
    raw_scopes: Any, *, field_name: str = "OAuth granted scopes"
) -> tuple[str, ...]:
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


def _oauth_activation_review(
    exchanged: dict[str, Any],
    credential_metadata: dict[str, Any],
    granted_scopes: tuple[str, ...],
    reconnect_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        provider_id, provider_subject, provider_account = (
            db.validate_managed_oauth_account_identity(credential_metadata)
        )
    except db.ManagedOAuthCredentialError as exc:
        raise OAuthError(str(exc)) from exc
    if exchanged.get("provider") != provider_id:
        raise OAuthError(
            "OAuth exchange provider does not match verified provider identity"
        )
    review = {
        "credential_type": "oauth2",
        "provider": provider_id,
        "provider_subject": provider_subject,
        "provider_account": provider_account,
        "scopes": list(granted_scopes),
        "credential_name": exchanged.get("name"),
        "metadata_keys": sorted(credential_metadata),
        "expires_at_epoch_ms": exchanged.get("expiresAtEpochMs"),
    }
    if provider_id == "x":
        x_app_id = credential_metadata.get("x_app_id")
        if not isinstance(x_app_id, str) or not x_app_id:
            raise OAuthError("X OAuth credential is missing its app binding")
        review["x_app_id"] = x_app_id
    if reconnect_binding is not None:
        review["reconnect_credential_id"] = reconnect_binding["credential_id"]
        review["reconnect_credential_version"] = reconnect_binding["credential_version"]
    return review


def _oauth_reconnect_binding_from_credential(
    credential: dict[str, Any],
) -> dict[str, Any]:
    if credential.get("kind") != "oauth2":
        raise OAuthError("OAuth reconnect credential kind is invalid")
    try:
        provider_id, provider_subject, provider_account = (
            db.validate_managed_oauth_account_identity(credential.get("metadata"))
        )
    except db.ManagedOAuthCredentialError as exc:
        raise OAuthError(str(exc)) from exc
    version = credential.get("credential_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise OAuthError("OAuth reconnect credential version is invalid")
    return {
        "credential_id": str(credential["id"]),
        "credential_version": version,
        "provider": provider_id,
        "provider_subject": provider_subject,
        "provider_account": provider_account,
    }


def _validate_oauth_reconnect_callback(
    exchanged: dict[str, Any],
    credential_metadata: dict[str, Any],
) -> dict[str, Any] | None:
    reconnect_binding = exchanged.get("reconnect")
    if reconnect_binding is None:
        return None
    if not isinstance(reconnect_binding, dict) or set(reconnect_binding) != {
        "credential_id",
        "credential_version",
        "provider",
        "provider_subject",
        "provider_account",
    }:
        raise OAuthError("OAuth reconnect binding is malformed")
    credential_id = reconnect_binding.get("credential_id")
    expected_version = reconnect_binding.get("credential_version")
    if not isinstance(credential_id, str) or not credential_id:
        raise OAuthError("OAuth reconnect credential ID is invalid")
    if (
        not isinstance(expected_version, int)
        or isinstance(expected_version, bool)
        or expected_version < 1
    ):
        raise OAuthError("OAuth reconnect credential version is invalid")
    current = db.get_credential(credential_id)
    if current is None:
        raise OAuthError("OAuth reconnect credential is no longer active")
    current_binding = _oauth_reconnect_binding_from_credential(current)
    try:
        provider_id, provider_subject, provider_account = (
            db.validate_managed_oauth_account_identity(credential_metadata)
        )
    except db.ManagedOAuthCredentialError as exc:
        raise OAuthError(str(exc)) from exc
    expected = {
        "credential_id": credential_id,
        "credential_version": expected_version,
        "provider": reconnect_binding.get("provider"),
        "provider_subject": reconnect_binding.get("provider_subject"),
        "provider_account": reconnect_binding.get("provider_account"),
    }
    if current_binding != expected:
        raise OAuthError("OAuth reconnect credential changed during authorization")
    if (provider_id, provider_subject, provider_account) != (
        expected["provider"],
        expected["provider_subject"],
        expected["provider_account"],
    ):
        raise OAuthError(
            "OAuth reconnect must verify the exact existing provider subject and account"
        )
    if exchanged.get("name") != current.get("name"):
        raise OAuthError("OAuth reconnect credential name changed during authorization")
    return expected


def _ensure_oauth_exchange_revocation_work(
    exchanged: dict[str, Any],
    *,
    actor_id: str,
) -> str:
    existing = exchanged.get("revocationWorkId")
    if isinstance(existing, str) and re.fullmatch(r"[0-9a-f-]{36}", existing):
        return existing
    provider_id = exchanged.get("provider")
    try:
        token_secret = json.loads(str(exchanged.get("secret") or ""))
        if not isinstance(provider_id, str) or not isinstance(token_secret, dict):
            raise OAuthError("OAuth exchange revocation material is malformed")
        work_id = db.create_oauth_revocation_work(
            provider_id=provider_id,
            actor_id=actor_id,
            source="callback_validation",
            secret=json.dumps(token_secret, separators=(",", ":"), sort_keys=True),
        )
    except (
        db.ManagedOAuthCredentialError,
        db.MetadataStoreError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise OAuthError(
            "OAuth exchange revocation material could not be retained"
        ) from exc
    exchanged["revocationWorkId"] = work_id
    return work_id


def _revoke_rejected_oauth_exchange(
    exchanged: dict[str, Any],
    *,
    actor_id: str,
    rejection_reason: str = "callback_validation_failed",
) -> None:
    provider_id = exchanged.get("provider")
    result = "retained"
    reason = None
    try:
        work_id = _ensure_oauth_exchange_revocation_work(exchanged, actor_id=actor_id)
        db.mark_oauth_revocation_work_pending(
            work_id,
            error=rejection_reason[:500],
        )
        _reconcile_oauth_revocations()
        retained = db.get_oauth_revocation_work_status(work_id)
        if retained is None:
            result = "revoked"
        elif retained["attempts"]:
            result = "retained_for_retry"
            reason = "provider_revocation_failed"
    except (
        OAuthError,
        db.ManagedOAuthCredentialError,
        db.MetadataStoreError,
        ValueError,
    ):
        try:
            token_secret = json.loads(str(exchanged.get("secret") or ""))
            if not isinstance(provider_id, str) or not isinstance(token_secret, dict):
                raise OAuthError("rejected OAuth exchange is malformed")
            revoke_oauth_token(provider_id=provider_id, token_secret=token_secret)
            result = "revoked"
        except (OAuthError, json.JSONDecodeError, TypeError, ValueError):
            result = "failed"
            reason = "revocation_retention_failed"
    db.record_audit_event(
        (
            "credential.oauth_reconnect_rejected"
            if isinstance(exchanged.get("reconnect"), dict)
            else "credential.oauth_exchange_rejected"
        ),
        {
            "provider": provider_id,
            "credential_id": (exchanged.get("reconnect") or {}).get("credential_id")
            if isinstance(exchanged.get("reconnect"), dict)
            else None,
            "result": result,
            "reason": reason,
            "rejection_reason": rejection_reason,
        },
        actor_id=actor_id,
    )


def _revoke_rejected_oauth_refresh(
    refreshed: dict[str, Any],
    *,
    provider_id: str,
    rejection_reason: str,
) -> None:
    issued_secret = refreshed.get("revocationSecret") or refreshed.get("secret")
    exchange = {
        "provider": provider_id,
        "secret": issued_secret,
        "createdBy": "oauth-refresh",
        "revocationWorkId": refreshed.get("revocationWorkId"),
    }
    _revoke_rejected_oauth_exchange(
        exchange,
        actor_id="oauth-refresh",
        rejection_reason=rejection_reason,
    )


def _oauth_activation_payload_digest(
    *,
    review: dict[str, Any],
    secret: str,
) -> str:
    return _control_plane_payload_digest(
        {
            "action": "credential.oauth.activate",
            "review": review,
            "encrypted_token_source_sha256": "sha256:"
            + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        }
    )


@app.post("/api/oauth/start")
def oauth_start(
    payload: OAuthStartRequest,
    response: Response,
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
    setup_session = None
    if payload.setup_session_id is not None:
        if payload.credential_id is not None:
            raise HTTPException(
                status_code=409,
                detail="a durable setup session can connect a new OAuth grant but cannot reconnect an existing grant",
            )
        setup_session = _load_setup_session_for_identity(
            payload.setup_session_id,
            identity,
            mutate=True,
        )
        if setup_session["owner_id"] != identity.user_id:
            raise HTTPException(
                status_code=403,
                detail="only the setup owner can initiate OAuth consent",
            )
        if setup_session["phase"] != "created":
            raise HTTPException(
                status_code=409,
                detail="setup session has already started OAuth consent",
            )
        if setup_session["revision"] != payload.setup_revision:
            _setup_session_error(
                db.SetupSessionStaleRevisionError(
                    payload.setup_session_id,
                    int(payload.setup_revision),
                    int(setup_session["revision"]),
                )
            )
        if (
            setup_session.get("route_id") is None
            or setup_session.get("route_policy_digest") is None
        ):
            raise HTTPException(
                status_code=409,
                detail="setup OAuth consent requires an authoritative route and reviewed policy digest",
            )
        _require_authoritative_setup_route_binding(
            route_id=setup_session.get("route_id"),
            route_policy_digest=setup_session.get("route_policy_digest"),
        )
    reconnect_binding = None
    credential_name = payload.credential_name
    authorization_metadata = payload.metadata
    requested_scope_input = payload.scopes
    mutation_action = "credential.create"
    mutation_resource_id = None
    if payload.credential_id:
        existing = db.get_credential(payload.credential_id)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail="OAuth reconnect credential not found or inactive",
            )
        try:
            reconnect_binding = _oauth_reconnect_binding_from_credential(existing)
        except OAuthError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        normalized_provider = normalize_provider_id(payload.provider)
        if normalized_provider != reconnect_binding["provider"]:
            raise HTTPException(
                status_code=409,
                detail="OAuth reconnect provider does not match the existing credential",
            )
        if normalized_provider == "google":
            raise HTTPException(
                status_code=409,
                detail=(
                    "Google revocation invalidates the account/project grant rather than one token. "
                    "Disconnect this credential, then connect the Google account again."
                ),
            )
        if (
            payload.credential_name is not None
            and payload.credential_name.strip() != existing["name"]
        ):
            raise HTTPException(
                status_code=409,
                detail="OAuth reconnect preserves the existing credential name",
            )
        if payload.metadata and payload.metadata != existing["metadata"]:
            raise HTTPException(
                status_code=409,
                detail="OAuth reconnect preserves existing credential metadata until provider verification",
            )
        credential_name = existing["name"]
        authorization_metadata = existing["metadata"]
        if requested_scope_input is None:
            existing_scopes = existing["metadata"].get("scopes")
            if not isinstance(existing_scopes, list):
                raise HTTPException(
                    status_code=409,
                    detail="OAuth reconnect credential scopes are invalid",
                )
            requested_scope_input = existing_scopes
        mutation_action = "credential.update"
        mutation_resource_id = payload.credential_id
    try:
        requested_scopes = list(
            resolve_requested_scopes(payload.provider, requested_scope_input)
        )
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    mutation_payload = payload.model_dump(exclude={"mfa"})
    mutation_payload["scopes"] = requested_scopes
    mutation_payload["credential_name"] = credential_name
    mutation_payload["metadata"] = authorization_metadata
    payload_digest = _control_plane_payload_digest(mutation_payload)
    mfa = _require_control_plane_mutation_mfa(
        action=mutation_action,
        resource_id=mutation_resource_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    # The account identity is unknown here. Two-person review is deferred until
    # the callback binds the exact provider subject and granted scopes.
    two_person = None
    browser_nonce = secrets.token_urlsafe(32)
    try:
        started = create_authorization_url(
            provider_id=payload.provider,
            credential_name=credential_name,
            scopes=requested_scopes,
            metadata=authorization_metadata,
            actor_id=identity.user_id,
            browser_nonce=browser_nonce,
            control_plane_mfa=mfa,
            control_plane_approval=two_person,
            reconnect_binding=reconnect_binding,
            setup_session_id=payload.setup_session_id,
        )
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if setup_session is not None:
        state_digest = (
            "sha256:" + hashlib.sha256(started["state"].encode("ascii")).hexdigest()
        )
        try:
            setup_session = db.transition_setup_session(
                setup_session["id"],
                expected_revision=int(payload.setup_revision),
                transition="bind_oauth_flow",
                actor_id=identity.user_id,
                updates={
                    "oauth_provider": started["provider"],
                    "oauth_state_digest": state_digest,
                },
                event={"scopes": started["scopes"]},
            )
        except db.SetupSessionError as exc:
            try:
                consume_state(
                    provider_id=payload.provider,
                    state=started["state"],
                    browser_nonce=browser_nonce,
                )
            except OAuthError:
                pass
            _setup_session_error(exc)
        _drain_setup_session_audit_outbox()
    db.record_audit_event(
        "credential.oauth_authorization_started",
        {
            "provider": started["provider"],
            "credential_name": credential_name,
            "reconnect_credential_id": mutation_resource_id,
            "reconnect_credential_version": (
                reconnect_binding.get("credential_version")
                if reconnect_binding
                else None
            ),
            "scopes": started["scopes"],
            "state_hash": "sha256:"
            + hashlib.sha256(started["state"].encode("ascii")).hexdigest(),
            "expires_at_epoch": started["expiresAtEpoch"],
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
            "post_identity_activation_approval": _control_plane_two_person_required(
                "credential.oauth.activate"
            ),
            "payload_digest": payload_digest,
        },
        actor_id=identity.user_id,
    )
    response.set_cookie(
        browser_cookie_name(started["state"]),
        browser_nonce,
        max_age=max(1, started["expiresAtEpoch"] - int(time.time())),
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    if setup_session is not None:
        started["setupSession"] = _setup_session_public(setup_session)
    return started


def _fail_bound_oauth_setup_session(
    *,
    setup_session_id: object,
    actor_id: object,
    provider_id: str,
    state: str,
    reason: str,
) -> None:
    if not isinstance(setup_session_id, str) or not isinstance(actor_id, str):
        return
    try:
        normalized_provider = normalize_provider_id(provider_id)
    except OAuthError:
        return
    setup_session = db.get_setup_session(setup_session_id)
    state_digest = "sha256:" + hashlib.sha256(state.encode("ascii")).hexdigest()
    if not (
        setup_session is not None
        and setup_session["status"] == "active"
        and setup_session["phase"] == "oauth_started"
        and setup_session["owner_id"] == actor_id
        and setup_session["oauth_provider"] == normalized_provider
        and isinstance(setup_session.get("oauth_state_digest"), str)
        and hmac.compare_digest(setup_session["oauth_state_digest"], state_digest)
    ):
        return
    try:
        db.transition_setup_session(
            setup_session_id,
            expected_revision=setup_session["revision"],
            transition="fail",
            actor_id=actor_id,
            event={"reason": reason, "provider": normalized_provider},
        )
        _drain_setup_session_audit_outbox()
    except db.SetupSessionError:
        return


@app.get("/api/oauth/callback/{provider_id}")
def oauth_callback(
    provider_id: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> HTMLResponse:
    oauth_cookie_name = None
    browser_nonce = ""
    if state:
        try:
            oauth_cookie_name = browser_cookie_name(state)
        except OAuthError:
            pass
        else:
            browser_nonce = request.cookies.get(oauth_cookie_name, "")
    if error:
        if not state:
            return HTMLResponse(
                "<h1>OAuth failed</h1><p>Missing state.</p>",
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        try:
            denied_state = consume_state(
                provider_id=provider_id,
                state=state,
                browser_nonce=browser_nonce,
            )
        except OAuthError as exc:
            detail = html.escape(str(exc))
            return HTMLResponse(
                f"<h1>OAuth failed</h1><p>{detail}</p>",
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        setup_session_id = denied_state.get("setup_session_id")
        _fail_bound_oauth_setup_session(
            setup_session_id=setup_session_id,
            actor_id=denied_state.get("actor_id"),
            provider_id=provider_id,
            state=state,
            reason="oauth_consent_denied",
        )
        detail = html.escape(error_description or error)
        denied = HTMLResponse(
            f"<h1>OAuth denied</h1><p>{detail}</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
        if oauth_cookie_name:
            denied.delete_cookie(
                oauth_cookie_name, path="/", secure=True, httponly=True, samesite="lax"
            )
        return denied
    if not code or not state:
        return HTMLResponse(
            "<h1>OAuth failed</h1><p>Missing code or state.</p>",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )
    exchanged: dict[str, Any] | None = None
    setup_session: dict[str, Any] | None = None
    setup_state_digest: str | None = None
    try:
        exchanged = exchange_authorization_code(
            provider_id=provider_id,
            code=code,
            state=state,
            browser_nonce=browser_nonce,
        )
        if not isinstance(exchanged, dict):
            raise OAuthError("OAuth token exchange result is malformed")
        actor_id = str(exchanged.get("createdBy") or "oauth-callback")
        setup_session_id = exchanged.get("setupSessionId")
        if setup_session_id is not None:
            if not isinstance(setup_session_id, str):
                raise OAuthError("OAuth setup session binding is malformed")
            setup_session = db.get_setup_session(setup_session_id)
            setup_state_digest = (
                "sha256:" + hashlib.sha256(state.encode("ascii")).hexdigest()
            )
            if not (
                setup_session is not None
                and setup_session["status"] == "active"
                and setup_session["phase"] == "oauth_started"
                and setup_session["owner_id"] == actor_id
                and setup_session["oauth_provider"]
                == normalize_provider_id(provider_id)
                and isinstance(setup_session.get("oauth_state_digest"), str)
                and hmac.compare_digest(
                    setup_session["oauth_state_digest"], setup_state_digest
                )
            ):
                raise OAuthError(
                    "OAuth callback does not match the active setup session"
                )
        revocation_work_id = _ensure_oauth_exchange_revocation_work(
            exchanged,
            actor_id=actor_id,
        )
        granted_scopes = _canonical_oauth_granted_scopes(exchanged.get("scopes"))
        credential_metadata = exchanged.get("metadata")
        if not isinstance(credential_metadata, dict):
            raise OAuthError("OAuth credential metadata is malformed")
        metadata_scopes = _canonical_oauth_granted_scopes(
            credential_metadata.get("scopes"),
            field_name="OAuth credential metadata scopes",
        )
        if metadata_scopes != granted_scopes:
            raise OAuthError(
                "OAuth credential metadata does not match the provider-granted scopes"
            )
        credential_metadata = {**credential_metadata, "scopes": list(granted_scopes)}
        reconnect_binding = _validate_oauth_reconnect_callback(
            exchanged, credential_metadata
        )
        activation_review = _oauth_activation_review(
            exchanged,
            credential_metadata,
            granted_scopes,
            reconnect_binding,
        )
    except OAuthError as exc:
        failed_setup_id = (
            exchanged.get("setupSessionId")
            if isinstance(exchanged, dict)
            else exc.setup_session_id
        )
        failed_actor_id = (
            exchanged.get("createdBy") if isinstance(exchanged, dict) else exc.actor_id
        )
        if isinstance(exchanged, dict):
            _revoke_rejected_oauth_exchange(
                exchanged,
                actor_id=str(exchanged.get("createdBy") or "oauth-callback"),
                rejection_reason=str(exc),
            )
        _fail_bound_oauth_setup_session(
            setup_session_id=failed_setup_id,
            actor_id=failed_actor_id,
            provider_id=provider_id,
            state=state,
            reason="oauth_exchange_failed",
        )
        detail = html.escape(str(exc))
        failed = HTMLResponse(
            f"<h1>OAuth failed</h1><p>{detail}</p>",
            status_code=409
            if isinstance(exchanged, dict) and exchanged.get("reconnect") is not None
            else 400,
            headers={"Cache-Control": "no-store"},
        )
        if oauth_cookie_name:
            failed.delete_cookie(
                oauth_cookie_name, path="/", secure=True, httponly=True, samesite="lax"
            )
        return failed
    assert exchanged is not None
    actor_id = exchanged.get("createdBy") or "oauth-callback"
    revocation_work_id = str(exchanged["revocationWorkId"])
    if _control_plane_two_person_required("credential.oauth.activate"):
        payload_digest = _oauth_activation_payload_digest(
            review=activation_review,
            secret=exchanged["secret"],
        )
        try:
            pending = db.create_pending_oauth_credential(
                name=exchanged["name"],
                kind=exchanged["kind"],
                secret=exchanged["secret"],
                metadata=credential_metadata,
                requester_id=actor_id,
                payload_digest=payload_digest,
                review=activation_review,
                ttl_seconds=OAUTH_PENDING_CREDENTIAL_TTL_SECONDS,
                target_credential_id=(
                    reconnect_binding["credential_id"] if reconnect_binding else None
                ),
                target_credential_version=(
                    reconnect_binding["credential_version"]
                    if reconnect_binding
                    else None
                ),
                revocation_work_id=revocation_work_id,
                setup_session_id=(
                    setup_session["id"] if setup_session is not None else None
                ),
                setup_expected_revision=(
                    int(setup_session["revision"])
                    if setup_session is not None
                    else None
                ),
                setup_actor_id=(str(actor_id) if setup_session is not None else None),
                setup_oauth_provider=(
                    str(exchanged["provider"])
                    if setup_session is not None
                    else None
                ),
                setup_oauth_state_digest=(
                    setup_state_digest if setup_session is not None else None
                ),
            )
            if setup_session is not None:
                setup_session = db.get_setup_session(setup_session["id"])
                if setup_session is None:
                    raise db.SetupSessionNotFoundError(
                        "setup session disappeared after atomic OAuth staging"
                    )
                _drain_setup_session_audit_outbox()
        except db.SetupSessionError as exc:
            _revoke_rejected_oauth_exchange(
                exchanged,
                actor_id=str(actor_id),
                rejection_reason=str(exc),
            )
            _fail_bound_oauth_setup_session(
                setup_session_id=(setup_session or {}).get("id"),
                actor_id=str(actor_id),
                provider_id=provider_id,
                state=state,
                reason="oauth_setup_binding_failed",
            )
            failed = HTMLResponse(
                f"<h1>OAuth failed</h1><p>{html.escape(str(exc))}</p>",
                status_code=409,
                headers={"Cache-Control": "no-store"},
            )
            if oauth_cookie_name:
                failed.delete_cookie(
                    oauth_cookie_name,
                    path="/",
                    secure=True,
                    httponly=True,
                    samesite="lax",
                )
            return failed
        except (
            db.ManagedOAuthCredentialError,
            db.MetadataStoreError,
            ValueError,
        ) as exc:
            _revoke_rejected_oauth_exchange(
                exchanged,
                actor_id=str(actor_id),
                rejection_reason=str(exc),
            )
            _fail_bound_oauth_setup_session(
                setup_session_id=(setup_session or {}).get("id"),
                actor_id=str(actor_id),
                provider_id=provider_id,
                state=state,
                reason="oauth_credential_persistence_failed",
            )
            db.record_audit_event(
                "credential.oauth_pending_failed",
                {
                    "provider": exchanged["provider"],
                    "provider_subject": exchanged.get("providerSubject"),
                    "reason": type(exc).__name__,
                },
                actor_id=actor_id,
            )
            failed = HTMLResponse(
                "<h1>OAuth failed</h1><p>The verified credential could not be staged for approval.</p>",
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
            if oauth_cookie_name:
                failed.delete_cookie(
                    oauth_cookie_name,
                    path="/",
                    secure=True,
                    httponly=True,
                    samesite="lax",
                )
            return failed
        db.record_audit_event(
            "credential.oauth_pending_approval",
            {
                "pending_credential_id": pending["id"],
                **activation_review,
                "payload_digest": payload_digest,
                "expires_at": pending["expires_at"],
                "pre_identity_control_plane_mfa": exchanged.get("controlPlaneMfa"),
                "pre_identity_control_plane_approval": exchanged.get(
                    "controlPlaneApproval"
                ),
            },
            actor_id=actor_id,
        )
        account = html.escape(str(activation_review["provider_account"]))
        pending_message = (
            "The replacement grant is encrypted but not active. The existing credential and policy "
            "assignments remain unchanged until exact-account approval."
            if reconnect_binding is not None
            else "The grant is encrypted but not active. Return to the portal to request exact-account approval."
        )
        connected = HTMLResponse(
            f"""
            <h1>OAuth account verified</h1>
            <p><strong>{account}</strong>: {pending_message}</p>
            <script>
              setTimeout(() => {{ window.location.href = {json.dumps("/?setup=" + setup_session["id"] if setup_session is not None else "/")}; }}, 1200);
            </script>
            """,
            headers={"Cache-Control": "no-store"},
        )
    else:
        try:
            if reconnect_binding is not None:
                credential = db.reconnect_oauth_credential(
                    reconnect_binding["credential_id"],
                    expected_version=reconnect_binding["credential_version"],
                    secret=exchanged["secret"],
                    metadata=credential_metadata,
                    revocation_work_id=revocation_work_id,
                )
            else:
                credential = db.create_credential(
                    exchanged["name"],
                    exchanged["kind"],
                    exchanged["secret"],
                    credential_metadata,
                    revocation_work_id=revocation_work_id,
                    setup_session_id=(
                        setup_session["id"] if setup_session is not None else None
                    ),
                    setup_expected_revision=(
                        int(setup_session["revision"])
                        if setup_session is not None
                        else None
                    ),
                    setup_actor_id=(
                        str(actor_id) if setup_session is not None else None
                    ),
                    setup_oauth_provider=(
                        str(exchanged["provider"])
                        if setup_session is not None
                        else None
                    ),
                    setup_oauth_state_digest=(
                        setup_state_digest if setup_session is not None else None
                    ),
                )
            if setup_session is not None:
                setup_session = db.get_setup_session(setup_session["id"])
                if setup_session is None:
                    raise db.SetupSessionNotFoundError(
                        "setup session disappeared after atomic OAuth activation"
                    )
                _drain_setup_session_audit_outbox()
        except db.SetupSessionError as exc:
            _revoke_rejected_oauth_exchange(
                exchanged,
                actor_id=str(actor_id),
                rejection_reason=str(exc),
            )
            _fail_bound_oauth_setup_session(
                setup_session_id=(setup_session or {}).get("id"),
                actor_id=str(actor_id),
                provider_id=provider_id,
                state=state,
                reason="oauth_setup_binding_failed",
            )
            failed = HTMLResponse(
                f"<h1>OAuth failed</h1><p>{html.escape(str(exc))}</p>",
                status_code=409,
                headers={"Cache-Control": "no-store"},
            )
            if oauth_cookie_name:
                failed.delete_cookie(
                    oauth_cookie_name,
                    path="/",
                    secure=True,
                    httponly=True,
                    samesite="lax",
                )
            return failed
        except (
            db.ManagedOAuthCredentialError,
            db.MetadataStoreError,
            ValueError,
        ) as exc:
            _revoke_rejected_oauth_exchange(
                exchanged,
                actor_id=str(actor_id),
                rejection_reason=str(exc),
            )
            _fail_bound_oauth_setup_session(
                setup_session_id=(setup_session or {}).get("id"),
                actor_id=str(actor_id),
                provider_id=provider_id,
                state=state,
                reason="oauth_credential_persistence_failed",
            )
            failed = HTMLResponse(
                f"<h1>OAuth failed</h1><p>{html.escape(str(exc))}</p>",
                status_code=409,
                headers={"Cache-Control": "no-store"},
            )
            if oauth_cookie_name:
                failed.delete_cookie(
                    oauth_cookie_name,
                    path="/",
                    secure=True,
                    httponly=True,
                    samesite="lax",
                )
            return failed
        runtime.invalidate_secret_leases(credential["id"])
        db.record_audit_event(
            "credential.oauth_reconnected"
            if reconnect_binding is not None
            else "credential.oauth_connected",
            {
                "credential_id": credential["id"],
                "name": credential["name"],
                "kind": credential["kind"],
                "credential_version": credential.get("credential_version"),
                "secret_kek_id": credential.get("secret_kek_id"),
                **activation_review,
                "control_plane_mfa": exchanged.get("controlPlaneMfa"),
                "control_plane_approval": exchanged.get("controlPlaneApproval"),
            },
            actor_id=actor_id,
        )
        heading = (
            "OAuth credential reconnected"
            if reconnect_binding is not None
            else "OAuth credential connected"
        )
        connected = HTMLResponse(
            f"""
            <h1>{heading}</h1>
            <p>The credential is encrypted in Serverware and remains assigned to its policy routes.</p>
            <script>
              setTimeout(() => {{ window.location.href = {json.dumps("/?setup=" + setup_session["id"] if setup_session is not None else "/")}; }}, 1200);
            </script>
            """,
            headers={"Cache-Control": "no-store"},
        )
    if oauth_cookie_name:
        connected.delete_cookie(
            oauth_cookie_name, path="/", secure=True, httponly=True, samesite="lax"
        )
    return connected


@app.get("/api/oauth/pending")
def oauth_pending_credentials(
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
    return {
        "pendingCredentials": db.list_pending_oauth_credentials(
            requester_id=(
                None
                if identity.has_any_role({"admin"})
                else identity.user_id
            )
        )
    }


@app.post("/api/oauth/pending/{pending_credential_id}/activate")
def oauth_pending_credential_activate(
    pending_credential_id: str,
    payload: OAuthPendingActivateRequest,
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
    pending = db.get_pending_oauth_credential(pending_credential_id)
    if pending is None:
        raise HTTPException(
            status_code=404, detail="pending OAuth credential not found or expired"
        )
    if pending["requester_id"] != identity.user_id:
        raise HTTPException(
            status_code=403,
            detail="only the OAuth requester can activate this credential",
        )
    if pending.get("status") != "pending":
        status = str(pending.get("status") or "unusable")
        raise HTTPException(
            status_code=410 if status == "expired" else 409,
            detail={
                "error": "oauth_pending_activation_not_usable",
                "reason": f"pending_credential_{status}",
                "pendingCredentialId": pending_credential_id,
            },
        )
    setup_session = db.get_setup_session_by_oauth_pending_credential(
        pending_credential_id
    )
    if setup_session is not None:
        if (
            payload.setup_session_id != setup_session["id"]
            or payload.setup_revision is None
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "oauth_setup_binding_required",
                    "setupSessionId": setup_session["id"],
                    "currentRevision": setup_session["revision"],
                },
            )
        if not (
            setup_session["status"] == "active"
            and setup_session["phase"] == "oauth_verified"
            and setup_session["owner_id"] == identity.user_id
            and setup_session["revision"] == payload.setup_revision
        ):
            if setup_session["revision"] != payload.setup_revision:
                _setup_session_error(
                    db.SetupSessionStaleRevisionError(
                        setup_session["id"],
                        int(payload.setup_revision),
                        int(setup_session["revision"]),
                    )
                )
            raise HTTPException(
                status_code=409,
                detail="pending OAuth grant no longer matches the setup session",
            )
    elif payload.setup_session_id is not None:
        raise HTTPException(
            status_code=409,
            detail="pending OAuth grant is not bound to that setup session",
        )
    action = "credential.oauth.activate"
    payload_digest = pending["payload_digest"]
    mfa = _require_control_plane_mutation_mfa(
        action=action,
        resource_id=pending_credential_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    approval_id = _control_plane_approval_id(payload.mfa)
    if not approval_id:
        approval = db.ensure_control_plane_approval(
            action=action,
            resource_id=pending_credential_id,
            payload_digest=payload_digest,
            requester_id=identity.user_id,
            request=pending["review"],
            ttl_seconds=CONTROL_PLANE_TWO_PERSON_TTL_SECONDS,
        )
        raise HTTPException(
            status_code=428,
            detail={
                "error": "control_plane_approval_required",
                "approvalId": approval["id"],
                "status": approval["status"],
                "action": action,
                "resourceId": pending_credential_id,
                "payloadDigest": payload_digest,
                "expiresAt": approval["expires_at"],
                "retry": {"mfa.approvalId": approval["id"]},
            },
        )
    try:
        result = db.activate_pending_oauth_credential(
            pending_credential_id,
            approval_id=approval_id,
            actor_id=identity.user_id,
            setup_session_id=setup_session["id"] if setup_session is not None else None,
            setup_expected_revision=(
                int(payload.setup_revision) if setup_session is not None else None
            ),
        )
    except db.SetupSessionError as exc:
        _setup_session_error(exc)
    except db.ManagedOAuthCredentialError as exc:
        detail = str(exc)
        if "revocation work capacity" in detail:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "oauth_reconnect_retirement_unavailable",
                    "reason": "revocation_capacity_exhausted",
                    "pendingCredentialId": pending_credential_id,
                    "approvalId": approval_id,
                },
            ) from exc
        raise HTTPException(status_code=409, detail=detail) from exc
    if not result.get("ok"):
        reason = str(result.get("reason") or "activation_failed")
        status_code = (
            404
            if reason == "pending_credential_not_found"
            else 410
            if reason == "pending_credential_expired"
            else 409
        )
        raise HTTPException(
            status_code=status_code,
            detail={
                "error": "oauth_pending_activation_not_usable",
                "reason": reason,
                "pendingCredentialId": pending_credential_id,
                "approvalId": approval_id,
            },
        )
    credential = result["credential"]
    approval = result["approval"]
    if setup_session is not None:
        setup_session = result["setup_session"]
        _drain_setup_session_audit_outbox()
    runtime.invalidate_secret_leases(credential["id"])
    db.record_audit_event(
        (
            "credential.oauth_reconnected"
            if pending.get("target_credential_id")
            else "credential.oauth_connected"
        ),
        {
            "credential_id": credential["id"],
            "name": credential["name"],
            "kind": credential["kind"],
            "credential_version": credential.get("credential_version"),
            "secret_kek_id": credential.get("secret_kek_id"),
            "pending_credential_id": pending_credential_id,
            "reconnect": bool(pending.get("target_credential_id")),
            **pending["review"],
            "control_plane_mfa": mfa,
            "control_plane_approval": {
                "required": True,
                "approval_id": approval["id"],
                "approved_by": approval.get("approved_by"),
                "approved_at": approval.get("approved_at"),
                "payload_digest": payload_digest,
            },
        },
        actor_id=identity.user_id,
    )
    return {
        "ok": True,
        "credential": credential,
        "approval": approval,
        **(
            {"setupSession": _setup_session_public(setup_session)}
            if setup_session is not None
            else {}
        ),
    }


@app.delete("/api/oauth/pending/{pending_credential_id}")
def oauth_pending_credential_cancel(
    pending_credential_id: str,
    identity: AdminIdentity = Depends(require_role("admin", "credential_owner")),
) -> dict[str, Any]:
    result = db.cancel_pending_oauth_credential(
        pending_credential_id,
        actor_id=identity.user_id,
    )
    if not result.get("ok"):
        reason = str(result.get("reason") or "cancel_failed")
        status_code = (
            404
            if reason == "pending_credential_not_found"
            else 403
            if reason == "requester_mismatch"
            else 409
        )
        raise HTTPException(
            status_code=status_code,
            detail={"error": "oauth_pending_cancel_failed", "reason": reason},
        )
    return {
        "ok": True,
        "revocation": _revoke_terminal_pending_oauth_credential(
            pending_credential_id,
            actor_id=identity.user_id,
        ),
    }


@app.post("/api/oauth/pending/{pending_credential_id}/revoke")
def oauth_pending_credential_revoke(
    pending_credential_id: str,
    identity: AdminIdentity = Depends(require_role("admin", "credential_owner")),
) -> dict[str, Any]:
    pending = db.get_pending_oauth_credential(pending_credential_id)
    if pending is None:
        raise HTTPException(
            status_code=404, detail="pending OAuth credential not found"
        )
    if pending["requester_id"] != identity.user_id and not identity.has_any_role(
        {"admin"}
    ):
        raise HTTPException(
            status_code=403,
            detail="only the OAuth requester or an admin can revoke this grant",
        )
    if pending.get("status") not in {"cancelled", "expired", "rejected"}:
        raise HTTPException(
            status_code=409, detail="pending OAuth credential is not terminal"
        )
    result = _revoke_terminal_pending_oauth_credential(
        pending_credential_id,
        actor_id=identity.user_id,
    )
    if not result.get("ok"):
        raise HTTPException(
            status_code=503, detail={"error": "oauth_revocation_failed", **result}
        )
    return result


@app.post("/api/oauth/issuance-uncertainties/{work_id}/resolve")
def oauth_issuance_uncertainty_resolve(
    work_id: str,
    payload: OAuthIssuanceUncertaintyResolveRequest,
    identity: AdminIdentity = Depends(require_role("admin", "credential_owner")),
) -> dict[str, Any]:
    uncertainty = db.get_oauth_revocation_work_status(work_id)
    if uncertainty is None or uncertainty.get("status") not in {
        "issuance_uncertain_unreported",
        "issuance_uncertain",
    }:
        raise HTTPException(status_code=404, detail="OAuth issuance uncertainty not found")
    if uncertainty.get("actor_id") != identity.user_id and not identity.has_any_role(
        {"admin"}
    ):
        raise HTTPException(
            status_code=403,
            detail="only the OAuth requester or an admin can resolve this uncertainty",
        )
    action = "credential.oauth.uncertain.resolve"
    mutation_payload = {
        "work_id": work_id,
        "confirmed_provider_revocation": payload.confirmed_provider_revocation,
        "note": payload.note,
        "provider": uncertainty["provider_id"],
        "source": uncertainty["source"],
    }
    payload_digest = _control_plane_payload_digest(mutation_payload)
    mfa = _require_control_plane_mutation_mfa(
        action=action,
        resource_id=work_id,
        payload_digest=payload_digest,
        mfa=payload.mfa,
        identity=identity,
    )
    with db.connect() as conn:
        two_person = _require_control_plane_two_person(
            action=action,
            resource_id=work_id,
            payload_digest=payload_digest,
            mfa=payload.mfa,
            identity=identity,
            request=mutation_payload,
            connection=conn,
        )
        result = db.resolve_oauth_issuance_uncertainty(
            work_id,
            actor_id=identity.user_id,
            _connection=conn,
        )
        if not result.get("ok"):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "oauth_issuance_uncertainty_not_resolvable",
                    "reason": result.get("reason"),
                },
            )
    db.record_audit_event(
        "credential.oauth_issuance_uncertainty_resolved",
        {
            "provider": result["provider_id"],
            "source": result["source"],
            "revocation_work_id": work_id,
            "confirmed_provider_revocation": True,
            "note": payload.note,
            "payload_digest": payload_digest,
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
        },
        actor_id=identity.user_id,
    )
    return {"ok": True, "resolved": result}


@app.post("/api/credentials")
def create_credential(
    payload: CredentialCreate,
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
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
    created = db.create_credential(
        payload.name, payload.kind, payload.secret, payload.metadata
    )
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
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True, exclude={"mfa"})
    payload_digest = _control_plane_payload_digest(
        {"credential_id": credential_id, "changes": changes}
    )
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
    identity: AdminIdentity = Depends(
        require_role("admin", "policy_author", "credential_owner")
    ),
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
    disconnect = _disconnect_credential(credential_id, actor_id=identity.user_id)
    deleted = disconnect["deleted"]
    provider_revoked = disconnect["provider_revoked"]
    if deleted:
        db.record_audit_event(
            "credential.deleted",
            {
                "credential_id": credential_id,
                "control_plane_mfa": mfa,
                "control_plane_approval": two_person,
                "payload_digest": payload_digest,
                "provider_revoked": provider_revoked,
            },
            actor_id=identity.user_id,
        )
        runtime.invalidate_secret_leases(credential_id)
    return {"deleted": deleted, "providerRevoked": provider_revoked}


@app.post("/api/routes")
def create_route(
    payload: RouteCreate,
    identity: AdminIdentity = Depends(require_role("admin", "policy_author")),
) -> dict[str, Any]:
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
    payload_digest = _control_plane_payload_digest(
        {"route_id": route_id, "changes": data}
    )
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
        raise HTTPException(
            status_code=409, detail="break-glass grant could not be approved"
        )
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
def approvals(
    status: str | None = None,
    _: AdminIdentity = Depends(require_role("approver", "auditor")),
) -> list[dict[str, Any]]:
    return db.list_approvals(status=status, limit=100)


@app.get("/api/approvals/{approval_id}/review")
def approval_review(
    approval_id: str,
    identity: AdminIdentity = Depends(require_role("approver", "auditor")),
) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    review = _approval_review_document(approval)
    review_digest = "sha256:" + hashlib.sha256(
        _canonical_json(review).encode("utf-8")
    ).hexdigest()
    receipt = None
    if approval["status"] == "pending" and not _approval_is_expired(approval):
        try:
            receipt = db.issue_approval_review_receipt(
                approval_request_id=approval_id,
                reviewer_id=identity.user_id,
                review_digest=review_digest,
            )
        except db.MetadataStoreError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        db.record_audit_event(
            "approval.review_opened",
            {
                "approval_request_id": approval_id,
                "review_digest": review_digest,
                "review_receipt_id": receipt["id"],
                "review_receipt_expires_at": receipt["expires_at"],
            },
            actor_id=identity.user_id,
        )
    review["review_digest"] = review_digest
    review["review_receipt"] = (
        {
            "id": receipt["id"],
            "expires_at": receipt["expires_at"],
        }
        if receipt
        else None
    )
    return review


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
        raise HTTPException(
            status_code=409, detail=f"approval is already {approval['status']}"
        )
    if _approval_is_expired(approval):
        raise HTTPException(status_code=409, detail="approval is expired")
    jit = _approval_jit_policy(approval, require_current_policy=True)
    _assert_approver_allowed(identity, jit)
    review_receipt_id = payload.review_receipt_id if payload else None
    if not review_receipt_id:
        raise HTTPException(
            status_code=412,
            detail="open the approval review before approving this request",
        )
    review_receipt = db.get_active_approval_review_receipt(
        review_receipt_id,
        approval_request_id=approval_id,
        reviewer_id=identity.user_id,
    )
    if review_receipt is None:
        raise HTTPException(
            status_code=412,
            detail="approval review receipt is invalid, expired, or already used",
        )
    authn_policy = _approval_authn_policy(jit)
    authn: dict[str, Any]
    if _webauthn_required(authn_policy) or (payload and payload.assertion):
        if not payload or not payload.assertion:
            raise HTTPException(
                status_code=412, detail="WebAuthn assertion required for this approval"
            )
        try:
            authn = verify_approval_assertion(
                approval,
                identity.user_id,
                authn_policy,
                payload.assertion,
                review_receipt,
            )
        except WebAuthnError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    else:
        authn = {
            "method": identity.auth_method,
            "user_id": identity.user_id,
            "review_receipt_id": review_receipt["id"],
            "review_digest": review_receipt["review_digest"],
        }
    try:
        updated = db.approve_request(
            approval_id,
            ttl_seconds=ttl_seconds,
            note=payload.note if payload else None,
            actor_id=identity.user_id,
            authn=authn,
            challenge_id=authn.get("challenge_id"),
            review_receipt_id=review_receipt["id"],
            review_digest=review_receipt["review_digest"],
            require_review_receipt=True,
        )
    except db.MetadataStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(
            status_code=409, detail="approval state changed before it could be approved"
        )
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
        key: value for key, value in gate_publish.items() if key != "payload"
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
        raise HTTPException(
            status_code=409, detail=f"approval is already {approval['status']}"
        )
    if _approval_is_expired(approval):
        raise HTTPException(status_code=409, detail="approval is expired")
    _assert_approver_allowed(identity, _approval_jit_policy(approval))
    updated = db.deny_request(
        approval_id,
        note=decision.reason if decision else None,
        actor_id=identity.user_id,
    )
    if not updated:
        raise HTTPException(
            status_code=409, detail="approval state changed before it could be denied"
        )
    return updated


@app.post("/api/approvals/{approval_id}/webauthn/options")
def approval_webauthn_options(
    approval_id: str,
    payload: ApprovalWebAuthnOptionsRequest,
    identity: AdminIdentity = Depends(require_role("approver")),
) -> dict[str, Any]:
    approval = db.get_approval_request(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval["status"] != "pending":
        raise HTTPException(status_code=409, detail="approval is not pending")
    jit = _approval_jit_policy(approval, require_current_policy=True)
    _assert_approver_allowed(identity, jit)
    review_receipt = db.get_active_approval_review_receipt(
        payload.review_receipt_id,
        approval_request_id=approval_id,
        reviewer_id=identity.user_id,
    )
    if review_receipt is None:
        raise HTTPException(
            status_code=412,
            detail="open or refresh the approval review before requesting WebAuthn",
        )
    return approval_options(
        approval,
        identity.user_id,
        _approval_authn_policy(jit),
        review_receipt,
    )


@app.post("/api/webauthn/register/options")
def webauthn_register_options(
    payload: WebAuthnRegistrationStart,
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> dict[str, Any]:
    existing = db.list_webauthn_credentials(identity.user_id)
    production_release = RELEASE_CHANNEL.strip().lower() not in {
        "dev",
        "development",
        "local",
        "test",
    }
    payload_digest = _control_plane_payload_digest(
        {
            "user_id": identity.user_id,
            "label": payload.label,
            "existing_credential_ids": sorted(
                str(item["credential_id"]) for item in existing
            ),
        }
    )
    if not existing:
        if production_release:
            if len(WEBAUTHN_BOOTSTRAP_TOKEN) < 32:
                raise HTTPException(
                    status_code=503,
                    detail="WebAuthn bootstrap token is not configured safely",
                )
            if not payload.bootstrap_token or not hmac.compare_digest(
                WEBAUTHN_BOOTSTRAP_TOKEN, payload.bootstrap_token
            ):
                raise HTTPException(
                    status_code=403,
                    detail="valid WebAuthn bootstrap token required for first enrollment",
                )
        authorization = {
            "mode": "bootstrap-token"
            if production_release
            else "development-bootstrap",
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
            request={
                "user_id": identity.user_id,
                "label": payload.label,
                "existing_credential_count": len(existing),
            },
        )
        authorization = {
            "mode": "existing-webauthn",
            "payload_digest": payload_digest,
            "existing_credential_count": len(existing),
            "control_plane_mfa": mfa,
            "control_plane_approval": two_person,
        }
    return registration_options(
        identity.user_id, payload.label, authorization=authorization
    )


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
            "registration_authorization": credential.pop(
                "_registration_authorization", None
            ),
        },
        actor_id=identity.user_id,
    )
    return credential


@app.get("/api/webauthn/credentials")
def webauthn_credentials(
    identity: AdminIdentity = Depends(require_role("admin", "approver")),
) -> list[dict[str, Any]]:
    items = []
    for item in db.list_webauthn_credentials(identity.user_id):
        redacted = dict(item)
        redacted.pop("public_key_cose", None)
        redacted.pop("dev_private_key_pem", None)
        items.append(redacted)
    return items


@app.get("/api/webauthn/trust/status")
def webauthn_trust_status_api(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
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
def dev_webauthn_credential(
    identity: AdminIdentity = Depends(require_role("admin")),
) -> dict[str, Any]:
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
def logs(
    limit: int = Query(100, ge=1, le=500),
    _: AdminIdentity = Depends(require_role("auditor")),
) -> list[dict[str, Any]]:
    return db.list_logs(limit=limit)


@app.get("/api/grants/status")
def grant_store_status(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    try:
        return grants.status()
    except grants.GrantStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/metadata/store/status")
def metadata_store_status(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
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
def audit_events(
    limit: int = Query(100, ge=1, le=500),
    _: AdminIdentity = Depends(require_role("auditor")),
) -> list[dict[str, Any]]:
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
    attestation_measurement: str | None = Query(
        default=None, alias="attestationMeasurement"
    ),
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
    attestation_measurement: str | None = Query(
        default=None, alias="attestationMeasurement"
    ),
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
def audit_store_status(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
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
        + hashlib.sha256(
            payload.recipient_nonce.encode("ascii", errors="replace")
        ).hexdigest(),
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
        actor_id=DATA_PLANE_INSTANCE_ID if authenticated else None,
    )


def _should_record_credential_lease_issuance(
    payload: CredentialLeaseRequest,
    credentials: list[dict[str, Any]],
) -> tuple[str, str, str, str, str, str, str] | None:
    state_digest = (
        "sha256:"
        + hashlib.sha256(
            _canonical_json(
                [
                    [item["credentialId"], int(item["credentialVersion"])]
                    for item in credentials
                ]
            ).encode("utf-8")
        ).hexdigest()
    )
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
    refreshed: dict[str, Any] | None = None
    try:
        for _ in range(2):
            credential = runtime.get_control_plane_credential(credential_id)
            if not credential or credential.get("kind") != "oauth2":
                return credential
            metadata = credential.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("oauth") is not True:
                return credential
            expires_at_epoch_ms = metadata.get("expires_at_epoch_ms")
            if not isinstance(expires_at_epoch_ms, int) or isinstance(
                expires_at_epoch_ms, bool
            ):
                raise OAuthError(
                    "managed OAuth credential has no valid access-token expiry"
                )
            now_epoch_ms = time.time_ns() // 1_000_000
            if expires_at_epoch_ms > now_epoch_ms + OAUTH_REFRESH_SKEW_SECONDS * 1000:
                return credential
            provider_id = metadata.get("provider_id")
            if not isinstance(provider_id, str) or not provider_id:
                raise OAuthError("managed OAuth credential has no provider binding")

            with db.oauth_refresh_lock(credential_id):
                runtime.invalidate_secret_leases(credential_id)
                credential = runtime.get_control_plane_credential(credential_id)
                if not credential:
                    return None
                metadata = credential.get("metadata")
                if (
                    credential.get("kind") != "oauth2"
                    or not isinstance(metadata, dict)
                    or metadata.get("oauth") is not True
                ):
                    return credential
                provider_id = metadata.get("provider_id")
                if not isinstance(provider_id, str) or not provider_id:
                    raise OAuthError("managed OAuth credential has no provider binding")
                expires_at_epoch_ms = (
                    metadata.get("expires_at_epoch_ms")
                    if isinstance(metadata, dict)
                    else None
                )
                now_epoch_ms = time.time_ns() // 1_000_000
                if (
                    isinstance(expires_at_epoch_ms, int)
                    and not isinstance(expires_at_epoch_ms, bool)
                    and expires_at_epoch_ms
                    > now_epoch_ms + OAUTH_REFRESH_SKEW_SECONDS * 1000
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
                refresh_revocation = {
                    "provider": provider_id,
                    "secret": refreshed.get("revocationSecret")
                    or refreshed.get("secret"),
                    "revocationWorkId": refreshed.get("revocationWorkId"),
                }
                refreshed["revocationWorkId"] = _ensure_oauth_exchange_revocation_work(
                    refresh_revocation,
                    actor_id="oauth-refresh",
                )
                refreshed_scopes = _canonical_oauth_granted_scopes(
                    refreshed.get("scopes")
                )
                refreshed_metadata = refreshed.get("metadata")
                if not isinstance(refreshed_metadata, dict):
                    raise OAuthError("OAuth refresh credential metadata is malformed")
                refreshed_metadata_scopes = _canonical_oauth_granted_scopes(
                    refreshed_metadata.get("scopes"),
                    field_name="OAuth refresh credential metadata scopes",
                )
                if refreshed_metadata_scopes != refreshed_scopes:
                    raise OAuthError(
                        "OAuth refresh metadata does not match the provider-granted scopes"
                    )
                refreshed_metadata = {
                    **refreshed_metadata,
                    "scopes": list(refreshed_scopes),
                }
                persisted, rotated = db.update_credential_secret_if_version(
                    credential_id,
                    expected_version=int(credential.get("credential_version") or 0),
                    secret=refreshed["secret"],
                    metadata=refreshed_metadata,
                    revocation_work_id=str(refreshed["revocationWorkId"]),
                )
                if not persisted:
                    raise OAuthError("OAuth credential disappeared during refresh")
                if not rotated:
                    if int(persisted.get("credential_version") or 0) != int(
                        credential.get("credential_version") or 0
                    ):
                        _revoke_rejected_oauth_refresh(
                            refreshed,
                            provider_id=provider_id,
                            rejection_reason="OAuth credential changed during refresh",
                        )
                        refreshed = None
                        runtime.invalidate_secret_leases(credential_id)
                        continue
                    refreshed = None
                    runtime.invalidate_secret_leases(credential_id)
                    return persisted
                persisted_refresh = refreshed
                refreshed = None
                runtime.invalidate_secret_leases(credential_id)
                db.record_audit_event(
                    "credential.oauth_refreshed",
                    {
                        "credential_id": credential_id,
                        "provider": provider_id,
                        "previous_credential_version": credential.get(
                            "credential_version"
                        ),
                        "credential_version": persisted.get("credential_version"),
                        "expires_at_epoch_ms": persisted_refresh["expiresAtEpochMs"],
                        "refresh_token_rotated": persisted_refresh[
                            "refreshTokenRotated"
                        ],
                        "scopes": list(refreshed_scopes),
                    },
                    actor_type="system",
                    actor_id="oauth-refresh",
                )
                return persisted
        raise OAuthError("OAuth credential changed repeatedly during refresh")
    except (OAuthError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if isinstance(refreshed, dict) and isinstance(provider_id, str):
            _revoke_rejected_oauth_refresh(
                refreshed,
                provider_id=provider_id,
                rejection_reason=str(exc),
            )
            refreshed = None
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
        "x.oauth": "x",
        "x.oauth2": "x",
        "google.oauth": "google",
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
    elif isinstance(raw_scopes, list) and all(
        isinstance(item, str) and item for item in raw_scopes
    ):
        scopes = raw_scopes
    else:
        raise HTTPException(
            status_code=503, detail="credential scope metadata is invalid"
        )
    if len(scopes) != len(set(scopes)):
        raise HTTPException(
            status_code=503, detail="credential scope metadata contains duplicates"
        )
    return frozenset(scopes)


def _assert_credential_policy_binding(
    credential: dict[str, Any], credential_policy: Any
) -> None:
    metadata = credential.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=503, detail="credential metadata is invalid")
    policy_provider = _normalized_credential_provider(credential_policy.provider)
    stored_provider = _normalized_credential_provider(
        metadata.get("provider_id") or metadata.get("provider")
    )
    if policy_provider not in {"", "generic"} and stored_provider != policy_provider:
        raise HTTPException(
            status_code=409,
            detail="stored credential provider does not match the active signed policy",
        )
    if (
        credential_policy.provider_subject is not None
        and credential.get("kind") != "oauth2"
    ):
        raise HTTPException(
            status_code=409,
            detail="signed provider account binding requires a verified OAuth credential",
        )
    if credential.get("kind") == "oauth2":
        try:
            verified_provider, stored_subject = db.validate_managed_oauth_identity(
                metadata
            )
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


def _credential_secret_for_lease(
    credential: dict[str, Any], credential_policy: Any
) -> str:
    secret = str(credential.get("secret") or "")
    if credential.get("kind") != "oauth2":
        return secret
    injection = (
        credential_policy.injection
        if isinstance(credential_policy.injection, dict)
        else {}
    )
    if (
        injection.get("type") != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise HTTPException(
            status_code=409,
            detail="managed OAuth credentials require canonical access-token-only bearer injection",
        )

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate OAuth token field")
            result[key] = value
        return result

    try:
        token = json.loads(secret, object_pairs_hook=reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="managed OAuth credential token material is malformed",
        ) from exc
    access_token = token.get("access_token") if isinstance(token, dict) else None
    if (
        not isinstance(access_token, str)
        or not access_token
        or len(access_token.encode("utf-8")) > 64 * 1024
    ):
        raise HTTPException(
            status_code=503, detail="managed OAuth access token is missing or oversized"
        )
    return _canonical_json({"access_token": access_token})


def _assert_credential_lease_route_binding(
    payload: CredentialLeaseRequest, snapshot: Any
) -> Any:
    if not hmac.compare_digest(snapshot.hash, payload.policy_hash):
        raise HTTPException(
            status_code=409, detail="data-plane policy hash is not active"
        )
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(
            status_code=409,
            detail="principal is not assigned to the requested active route",
        )
    if route.credential_ref is None or not hmac.compare_digest(
        route.credential_ref, payload.credential_id
    ):
        raise HTTPException(
            status_code=409,
            detail="credential does not match the requested active route",
        )
    credential_policy = snapshot.credentials.get(payload.credential_id)
    if credential_policy is None:
        raise HTTPException(
            status_code=409, detail="credential is not declared by the active policy"
        )
    return credential_policy


@app.post("/api/data-plane/credential-leases")
def data_plane_credential_leases(
    payload: CredentialLeaseRequest = Depends(_bounded_credential_lease_request),
) -> Response:
    authenticated = True
    try:
        snapshot = get_policy_snapshot()
        if not snapshot:
            raise HTTPException(
                status_code=503, detail="active signed policy bundle is unavailable"
            )
        credential_policy = _assert_credential_lease_route_binding(payload, snapshot)
        if not EXPECTED_DATA_PLANE_BINARY_DIGEST:
            raise HTTPException(
                status_code=503,
                detail="expected data-plane binary digest is not configured",
            )
        if not hmac.compare_digest(
            EXPECTED_DATA_PLANE_BINARY_DIGEST, payload.data_plane_binary_digest
        ):
            raise HTTPException(
                status_code=409,
                detail="data-plane binary digest does not match configured digest",
            )

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
        expected_recipient_key_id = (
            "sha256:" + hashlib.sha256(recipient_public_key).hexdigest()
        )
        if not hmac.compare_digest(expected_recipient_key_id, payload.recipient_key_id):
            raise HTTPException(
                status_code=400,
                detail="recipientKeyId does not match recipientPublicKey",
            )
        issued_at_epoch_ms = time.time_ns() // 1_000_000
        recipient_nonce_sha256 = "sha256:" + hashlib.sha256(recipient_nonce).hexdigest()
        if db.credential_lease_nonce_reserved(
            payload.recipient_key_id,
            recipient_nonce_sha256,
            now_epoch_ms=issued_at_epoch_ms,
        ):
            raise HTTPException(
                status_code=409, detail="recipient nonce has already been used"
            )
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
        replay_result = db.reserve_credential_lease_nonce(
            payload.recipient_key_id,
            recipient_nonce_sha256,
            now_epoch_ms=issued_at_epoch_ms,
        )
        if replay_result == "replay":
            raise HTTPException(
                status_code=409, detail="recipient nonce has already been used"
            )
        if replay_result == "capacity":
            raise HTTPException(
                status_code=503, detail="credential lease replay cache is at capacity"
            )
        if not (SECRET_LEASE_TTL_SECONDS > 0):
            raise HTTPException(
                status_code=503, detail="credential lease TTL is not configured safely"
            )

        ttl_ms = max(
            1,
            int(
                min(float(payload.max_ttl_seconds), SECRET_LEASE_TTL_SECONDS, 10.0)
                * 1000
            ),
        )
        expires_at_epoch_ms = issued_at_epoch_ms + ttl_ms

        credential = _credential_for_lease(payload.credential_id)
        if not credential:
            raise HTTPException(
                status_code=404, detail="requested credential is unavailable"
            )
        _assert_credential_policy_binding(credential, credential_policy)

        current_snapshot = get_policy_snapshot()
        if current_snapshot is None:
            raise HTTPException(
                status_code=503, detail="active signed policy bundle became unavailable"
            )
        current_credential_policy = _assert_credential_lease_route_binding(
            payload, current_snapshot
        )
        with db.credential_lease_snapshot(payload.credential_id) as current_credential:
            if not current_credential:
                raise HTTPException(
                    status_code=404, detail="requested credential became unavailable"
                )
            if int(current_credential.get("credential_version") or 0) != int(
                credential.get("credential_version") or 0
            ):
                raise HTTPException(
                    status_code=409,
                    detail="credential changed during lease authorization",
                )
            _assert_credential_policy_binding(
                current_credential, current_credential_policy
            )
            credential = current_credential
            metadata = credential.get("metadata") or {}
            credentials = [
                {
                    "credentialId": payload.credential_id,
                    "credentialVersion": int(credential["credential_version"]),
                    "secret": _credential_secret_for_lease(
                        credential, current_credential_policy
                    ),
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
            if (
                len(_canonical_json(plaintext).encode("utf-8"))
                > _CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES
            ):
                raise HTTPException(
                    status_code=503, detail="credential lease plaintext exceeds 4 MiB"
                )
            try:
                encrypted = encrypt_credential_lease_envelope(
                    recipient_public_key=recipient_public_key,
                    recipient_nonce=recipient_nonce,
                    aad=aad,
                    plaintext=plaintext,
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail="recipientPublicKey is not a valid X25519 public key",
                ) from exc
            response_body = _canonical_json({**aad, **encrypted}).encode("utf-8")
            if len(response_body) > _CREDENTIAL_LEASE_RESPONSE_MAX_BYTES:
                raise HTTPException(
                    status_code=503, detail="credential lease response exceeds 8 MiB"
                )
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
        raise HTTPException(
            status_code=503, detail="credential lease issuance failed"
        ) from exc

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
            raise HTTPException(
                status_code=503, detail="credential lease issuance audit is unavailable"
            ) from exc
    return Response(
        content=response_body,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/data-plane/audit")
def data_plane_audit(
    batch: DataPlaneAuditBatch,
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_AUDIT_INGEST_TOKEN
    )
    for item in batch.events:
        if not item.event_type.startswith("data_plane."):
            raise HTTPException(
                status_code=400,
                detail="data-plane audit event_type must start with data_plane.",
            )
        try:
            db.validate_audit_event(item.event)
        except db.AuditStoreError as exc:
            raise HTTPException(
                status_code=413,
                detail="canonical data-plane audit event exceeds 2 MiB",
            ) from exc
    recorded = db.record_audit_event_batch(
        [(item.event_type, item.event) for item in batch.events],
        actor_type="data-plane",
        actor_id=DATA_PLANE_INSTANCE_ID,
    )
    return {"ok": True, "accepted": len(recorded)}


@app.post("/api/data-plane/grants/consume")
def data_plane_grant_consume(
    payload: DataPlaneGrantConsume,
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_GRANT_CONSUME_TOKEN
    )
    if ATOMIC_RELEASE_AUTHORIZATION_ENABLED and RELEASE_CHANNEL.strip().lower() not in {
        "dev",
        "development",
        "local",
        "test",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "legacy grant mutation is disabled; use atomic release authorization"
            ),
        )
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if snapshot.hash != payload.policy_hash:
        raise HTTPException(
            status_code=409, detail="data-plane policy hash is not active"
        )
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(
            status_code=409,
            detail="data-plane principal is not assigned to active route",
        )
    if route.credential_ref and route.credential_ref != payload.credential_ref:
        raise HTTPException(
            status_code=409,
            detail="data-plane credential reference does not match active route",
        )
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
        raise HTTPException(
            status_code=409,
            detail="grant attempt id was already bound to a different request",
        )
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
        "body_sha256": (payload.canonical_request.get("request") or {}).get(
            "body_sha256"
        ),
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
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN
    )
    if ATOMIC_RELEASE_AUTHORIZATION_ENABLED and RELEASE_CHANNEL.strip().lower() not in {
        "dev",
        "development",
        "local",
        "test",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                "legacy rate-limit mutation is disabled; use atomic release authorization"
            ),
        )
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if not hmac.compare_digest(snapshot.hash, payload.policy_hash):
        raise HTTPException(
            status_code=409, detail="data-plane policy hash is not active"
        )
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(
            status_code=409,
            detail="data-plane principal is not assigned to active route",
        )
    expected_credential_ref = route.credential_ref or ""
    if not hmac.compare_digest(payload.credential_ref or "", expected_credential_ref):
        raise HTTPException(
            status_code=409,
            detail="data-plane credential reference does not match active route",
        )
    if expected_credential_ref:
        credential = db.get_credential(expected_credential_ref)
        if (
            not credential
            or int(credential.get("credential_version") or 0)
            != payload.credential_version
        ):
            raise HTTPException(
                status_code=409, detail="data-plane credential version is not current"
            )
    elif payload.credential_version != 0:
        raise HTTPException(
            status_code=409,
            detail="credential-less route must use credential version zero",
        )
    matching_constraints = [
        item
        for item in route.constraints
        if item.get("id") == payload.constraint_id and item.get("type") == "rateLimit"
    ]
    if (
        len(matching_constraints) != 1
        or matching_constraints[0].get("store", "local") != "shared"
    ):
        raise HTTPException(
            status_code=409,
            detail="shared rate-limit constraint is not active on the route",
        )
    constraint = matching_constraints[0]
    expected_max = int(constraint["max"])
    expected_window_seconds = int(constraint["windowSeconds"])
    if (
        payload.max_count != expected_max
        or payload.window_seconds != expected_window_seconds
    ):
        raise HTTPException(
            status_code=409,
            detail="shared rate-limit parameters do not match active policy",
        )
    operation_context = dict(payload.operation_context)
    operation_name = operation_context.get("operation")
    if not isinstance(operation_name, str):
        operation_name = ""
    if (payload.operation or "") != operation_name:
        raise HTTPException(
            status_code=409,
            detail="shared rate-limit operation does not match operationContext",
        )
    expected_counter_key = _rate_limit_counter_key(
        constraint=constraint,
        route_id=route.id,
        principal_id=payload.principal_id,
        credential_ref=route.credential_ref,
        credential_version=payload.credential_version,
        operation_context=operation_context,
    )
    if not hmac.compare_digest(payload.counter_key, expected_counter_key):
        raise HTTPException(
            status_code=409,
            detail="shared rate-limit counter key does not match active policy",
        )
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
            actor_id=DATA_PLANE_INSTANCE_ID,
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
    return (
        "sha256:"
        + hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()
    )


def _require_data_plane_token(
    x_serverware_data_plane_token: str | None, expected_token: str
) -> None:
    if not expected_token or not DATA_PLANE_INSTANCE_ID:
        raise HTTPException(
            status_code=503, detail="data-plane authentication is not configured"
        )
    if not x_serverware_data_plane_token or not hmac.compare_digest(
        x_serverware_data_plane_token, expected_token
    ):
        raise HTTPException(
            status_code=401, detail="data-plane authentication required"
        )


def _release_authorization_api_response(result: dict[str, Any]) -> dict[str, Any]:
    quotas = [
        {
            "counterKey": item.get("counter_key"),
            "constraintId": item.get("constraint_id"),
            "operation": item.get("operation"),
            "windowStartEpochMs": item.get("window_start_epoch_ms"),
            "windowSeconds": item.get("window_seconds"),
            "max": item.get("max"),
            "count": item.get("count"),
            "remaining": item.get("remaining"),
            "reservationState": item.get("reservation_state"),
        }
        for item in result.get("quotas") or []
    ]
    response = {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": bool(result.get("authorized")),
        "state": result.get("state"),
        "reason": result.get("reason"),
        "attemptId": result.get("attempt_id"),
        "bindingDigest": result.get("binding_digest"),
        "idempotentReplay": bool(result.get("idempotent_replay")),
        "grantId": result.get("grant_id"),
        "approvalRequestId": result.get("approval_request_id"),
        "reservationExpiresAtEpochMs": result.get(
            "reservation_expires_at_epoch_ms"
        ),
        "dispatchStartedAtEpochMs": result.get("dispatch_started_at_epoch_ms"),
        "dispatchExpiresAtEpochMs": result.get("dispatch_expires_at_epoch_ms"),
        "completionOutcome": result.get("completion_outcome"),
        "retryAfterSeconds": int(result.get("retry_after_seconds") or 0),
        "quotas": quotas,
        "store": {
            "backend": result.get("release_authorization_store_backend"),
            "ha": bool(result.get("release_authorization_store_ha")),
        },
    }
    if "approval_created" in result:
        response.update(
            {
                "approvalStatus": result.get("approval_status"),
                "approvalExpiresAt": result.get("approval_expires_at"),
                "approvalCreated": bool(result.get("approval_created")),
            }
        )
    return response


_RELEASE_CANONICAL_TOP_LEVEL_FIELDS = {
    "v",
    "principal",
    "client_ip",
    "route_id",
    "credential_ref",
    "credential_version",
    "policy_hash",
    "request",
    "operation",
}
_RELEASE_CANONICAL_REQUEST_FIELDS = {
    "method",
    "scheme",
    "authority",
    "path",
    "query",
    "headers",
    "body_sha256",
}
_RELEASE_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "token",
}
_RELEASE_HTTP_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
_RELEASE_DERIVED_DISPLAY_URL_MAX_BYTES = 16 * 1024
_RELEASE_APPROVAL_REVIEW_MAX_BYTES = 64 * 1024


def _release_canonical_text(
    value: Any,
    *,
    field: str,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HTTPException(
            status_code=409,
            detail=f"canonicalRequest {field} is invalid",
        )
    return value


def _release_authorization_approval_review(
    payload: DataPlaneReleaseAuthorizationReserve,
    route: Any,
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    canonical = payload.canonical_request
    if not isinstance(canonical, dict):
        raise HTTPException(
            status_code=409,
            detail="JIT release authorization requires canonicalRequest",
        )
    if set(canonical) != _RELEASE_CANONICAL_TOP_LEVEL_FIELDS or canonical.get("v") != 1:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest does not match the v1 request shape",
        )
    request = canonical.get("request")
    operation = canonical.get("operation")
    if (
        not isinstance(request, dict)
        or set(request) != _RELEASE_CANONICAL_REQUEST_FIELDS
        or not isinstance(operation, dict)
    ):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest does not match the v1 request shape",
        )
    client_ip = canonical.get("client_ip")
    if client_ip is not None:
        _release_canonical_text(client_ip, field="client_ip", maximum=256)

    expected_credential_version = (
        str(payload.credential_version) if payload.credential_version else None
    )
    canonical_credential_version = canonical.get("credential_version")
    credential_version_matches = (
        canonical_credential_version == expected_credential_version
        if expected_credential_version is not None
        else canonical_credential_version in {"0", "none"}
    )
    authoritative_bindings_match = (
        canonical.get("principal") == payload.principal_id
        and canonical.get("route_id") == payload.route_id
        and canonical.get("credential_ref") == payload.credential_ref
        and credential_version_matches
        and canonical.get("policy_hash") == payload.policy_hash
        and operation == payload.operation_context
    )
    if not authoritative_bindings_match:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest does not match authoritative reserve fields",
        )

    method = _release_canonical_text(
        request.get("method"), field="request.method", maximum=32
    )
    if method != method.upper():
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.method must be uppercase",
        )
    scheme = _release_canonical_text(
        request.get("scheme"), field="request.scheme", maximum=16
    )
    if scheme != scheme.lower() or scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.scheme is invalid",
        )
    authority = _release_canonical_text(
        request.get("authority"), field="request.authority", maximum=1024
    )
    if (
        authority != authority.lower()
        or authority != authority.strip()
        or any(character in authority for character in "@/\\?#")
    ):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.authority is invalid",
        )
    path = _release_canonical_text(
        request.get("path"), field="request.path", maximum=8192
    )
    if not path.startswith("/"):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.path is invalid",
        )
    route_host = str(route.host).rstrip(".").lower()
    if ":" in route_host and not route_host.startswith("["):
        route_host = f"[{route_host}]"
    route_port = int(route.port)
    default_port = 443 if route.scheme == "https" else 80 if route.scheme == "http" else None
    expected_authority = (
        route_host
        if route_port == default_port
        else f"{route_host}:{route_port}"
    )
    if (
        scheme != route.scheme
        or authority != expected_authority
        or method not in route.methods
        or route.match_path(path) is None
    ):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest target does not match the active route",
        )
    body_sha256 = request.get("body_sha256")
    if not isinstance(body_sha256, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", body_sha256
    ):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.body_sha256 is invalid",
        )
    headers = request.get("headers")
    if not isinstance(headers, dict) or any(
        not isinstance(name, str)
        or not isinstance(value, str)
        or _RELEASE_HTTP_FIELD_NAME_RE.fullmatch(name) is None
        or len(name.encode("utf-8")) > 256
        or len(value.encode("utf-8")) > 16 * 1024
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in name
        )
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in value
        )
        for name, value in headers.items()
    ):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.headers is invalid",
        )
    if headers.get("host") != authority:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request host does not match authority",
        )
    raw_query = request.get("query")
    if not isinstance(raw_query, list):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.query is invalid",
        )
    query: list[tuple[str, str]] = []
    for item in raw_query:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise HTTPException(
                status_code=409,
                detail="canonicalRequest request.query is invalid",
            )
        key = _release_canonical_text(
            item[0], field="request.query key", maximum=8192, allow_empty=True
        )
        value = _release_canonical_text(
            item[1], field="request.query value", maximum=8192, allow_empty=True
        )
        query.append((key, value))
    if query != sorted(query):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest request.query is not canonical",
        )

    try:
        canonical_json = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest is not canonical JSON",
        ) from exc
    request_digest = (
        "sha256:" + hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    )
    if not hmac.compare_digest(request_digest, payload.request_digest):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest does not hash to requestDigest",
        )
    if payload.operation_digest is None:
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest requires operationDigest",
        )
    operation_view = {
        "principal": canonical["principal"],
        "route_id": canonical["route_id"],
        "credential_ref": canonical["credential_ref"],
        "credential_version": canonical["credential_version"],
        "policy_hash": canonical["policy_hash"],
        "request": canonical["request"],
        "operation": canonical["operation"],
    }
    operation_json = json.dumps(
        operation_view,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    operation_digest = (
        "sha256:" + hashlib.sha256(operation_json.encode("utf-8")).hexdigest()
    )
    if not hmac.compare_digest(operation_digest, payload.operation_digest):
        raise HTTPException(
            status_code=409,
            detail="canonicalRequest operation view does not hash to operationDigest",
        )

    redacted_query = [
        (
            key,
            "redacted"
            if key.lower() in _RELEASE_SENSITIVE_QUERY_KEYS
            or any(part in key.lower() for part in SENSITIVE_REVIEW_KEY_PARTS)
            else value,
        )
        for key, value in query
    ]
    redacted_url = urlunsplit(
        (scheme, authority, path, urlencode(redacted_query), "")
    )
    if len(redacted_url.encode("utf-8")) > _RELEASE_DERIVED_DISPLAY_URL_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail="derived approval display URL exceeds 16 KiB",
        )
    redacted_display = {
        "method": method,
        "url": redacted_url,
        "route_id": payload.route_id,
        "principal": payload.principal_id,
        "body_sha256": body_sha256,
    }
    redacted_json = json.dumps(
        redacted_display,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    approval_payload_bytes = sum(
        len(value.encode("utf-8"))
        for value in (
            payload.route_id,
            method,
            redacted_url,
            payload.principal_id,
            payload.credential_ref or "",
            payload.policy_hash,
            payload.request_digest,
            payload.operation_digest,
            canonical_json,
            redacted_json,
        )
    )
    if approval_payload_bytes > _RELEASE_APPROVAL_REVIEW_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail="canonical approval review payload exceeds 64 KiB",
        )
    return method, redacted_url, canonical, redacted_display


def _release_authorization_route_claims(
    payload: DataPlaneReleaseAuthorizationReserve,
) -> tuple[Any, list[dict[str, Any]], bool]:
    snapshot = get_policy_snapshot()
    if not snapshot:
        raise HTTPException(status_code=503, detail="policy bundle missing")
    if not hmac.compare_digest(snapshot.hash, payload.policy_hash):
        raise HTTPException(
            status_code=409, detail="data-plane policy hash is not active"
        )
    route = _active_route_by_id(payload.route_id, snapshot=snapshot)
    if payload.principal_id not in route.principals and "*" not in route.principals:
        raise HTTPException(
            status_code=409,
            detail="data-plane principal is not assigned to active route",
        )
    expected_credential_ref = route.credential_ref or ""
    if not hmac.compare_digest(payload.credential_ref or "", expected_credential_ref):
        raise HTTPException(
            status_code=409,
            detail="data-plane credential reference does not match active route",
        )
    if expected_credential_ref:
        credential = db.get_credential(expected_credential_ref)
        if (
            not credential
            or int(credential.get("credential_version") or 0)
            != payload.credential_version
        ):
            raise HTTPException(
                status_code=409, detail="data-plane credential version is not current"
            )
    elif payload.credential_version != 0:
        raise HTTPException(
            status_code=409,
            detail="credential-less route must use credential version zero",
        )

    operation_context = dict(payload.operation_context)
    operation_name = operation_context.get("operation")
    if operation_name is not None and (
        not isinstance(operation_name, str)
        or not operation_name
        or len(operation_name.encode("utf-8")) > 256
    ):
        raise HTTPException(
            status_code=409,
            detail="release authorization operation must be a bounded non-empty string",
        )
    jit = route.jit or {}
    require_jit_grant = jit.get("required") is True
    if (
        require_jit_grant
        and (jit.get("binding") or {}).get("type") == "operationDigest"
        and payload.operation_digest is None
    ):
        raise HTTPException(
            status_code=409,
            detail="active route requires an operation-bound JIT grant",
        )

    shared_quotas: list[dict[str, Any]] = []
    for constraint in route.constraints:
        if (
            constraint.get("type") != "rateLimit"
            or constraint.get("store", "local") != "shared"
        ):
            continue
        key_policy = constraint.get("key") or {}
        scope = key_policy.get("scope") or [
            "principal",
            "credential",
            "route",
            "operation",
        ]
        required_operation_fields = set(key_policy.get("operationFields") or [])
        if "operation" in scope:
            required_operation_fields.add("operation")
        invalid_fields = sorted(
            field
            for field in required_operation_fields
            if not isinstance(operation_context.get(field), str)
            or not operation_context.get(field)
            or len(str(operation_context[field]).encode("utf-8")) > 256
        )
        if invalid_fields:
            raise HTTPException(
                status_code=409,
                detail=(
                    "release authorization is missing bounded operation fields: "
                    + ", ".join(invalid_fields)
                ),
            )
        shared_quotas.append(
            {
                "counter_key": _rate_limit_counter_key(
                    constraint=constraint,
                    route_id=route.id,
                    principal_id=payload.principal_id,
                    credential_ref=route.credential_ref,
                    credential_version=payload.credential_version,
                    operation_context=operation_context,
                ),
                "constraint_id": str(constraint["id"]),
                "operation": operation_name,
                "window_seconds": int(constraint["windowSeconds"]),
                "max_count": int(constraint["max"]),
            }
        )
    return route, shared_quotas, require_jit_grant


def _release_authorization_maintenance() -> None:
    try:
        db.reconcile_release_authorizations(
            limit=RELEASE_AUTHORIZATION_RECONCILE_LIMIT,
            actor_id=DATA_PLANE_INSTANCE_ID,
        )
        db.drain_release_authorization_audit_outbox(
            RELEASE_AUTHORIZATION_RECONCILE_LIMIT
        )
    except Exception:
        # The durable outbox remains authoritative when the audit sink is unavailable.
        return


@app.post("/api/data-plane/release-authorizations/reserve")
def data_plane_release_authorization_reserve(
    payload: DataPlaneReleaseAuthorizationReserve,
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN
    )
    route, shared_quotas, require_jit_grant = (
        _release_authorization_route_claims(payload)
    )
    approval_review = None
    if require_jit_grant or payload.canonical_request is not None:
        approval_review = _release_authorization_approval_review(payload, route)
    jit_approval_request = None
    if require_jit_grant:
        if approval_review is None:
            raise HTTPException(
                status_code=409,
                detail="JIT release authorization requires canonicalRequest",
            )
        method, url, canonical_request, redacted_display = approval_review
        jit = route.jit or {}
        jit_approval_request = {
            "method": method,
            "url": url,
            "canonical_request": canonical_request,
            "redacted_display": redacted_display,
            "pending_ttl_seconds": max(
                1, min(int(jit.get("pendingTtlSeconds", 300)), 3600)
            ),
            "grant_ttl_seconds": max(
                1, min(int(jit.get("ttlSeconds", 30)), 3600)
            ),
            "grant_max_uses": max(1, int(jit.get("maxUses", 1))),
        }
    _release_authorization_maintenance()
    try:
        result = db.reserve_release_authorization(
            attempt_id=payload.attempt_id,
            flow_id=payload.flow_id,
            principal_id=payload.principal_id,
            route_id=payload.route_id,
            credential_id=payload.credential_ref or "",
            credential_version=payload.credential_version,
            policy_hash=payload.policy_hash,
            request_digest=payload.request_digest,
            operation_digest=payload.operation_digest,
            operation_context=dict(payload.operation_context),
            shared_quotas=shared_quotas,
            require_jit_grant=require_jit_grant,
            reservation_ttl_seconds=RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS,
            jit_approval_request=jit_approval_request,
            actor_id=DATA_PLANE_INSTANCE_ID,
        )
    except db.ReleaseAuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except db.ReleaseAuthorizationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    _release_authorization_maintenance()
    return _release_authorization_api_response(result)


@app.post("/api/data-plane/release-authorizations/dispatch")
def data_plane_release_authorization_dispatch(
    payload: DataPlaneReleaseAuthorizationDispatch,
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN
    )
    try:
        result = db.dispatch_release_authorization(
            attempt_id=payload.attempt_id,
            binding_digest=payload.binding_digest,
            dispatch_ttl_seconds=RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS,
            actor_id=DATA_PLANE_INSTANCE_ID,
        )
    except db.ReleaseAuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except db.ReleaseAuthorizationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _release_authorization_maintenance()
    return _release_authorization_api_response(result)


@app.post("/api/data-plane/release-authorizations/complete")
def data_plane_release_authorization_complete(
    payload: DataPlaneReleaseAuthorizationComplete,
    x_serverware_data_plane_token: str | None = Header(
        default=None, alias="X-Serverware-Data-Plane-Token"
    ),
) -> dict[str, Any]:
    _require_data_plane_token(
        x_serverware_data_plane_token, DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN
    )
    try:
        result = db.complete_release_authorization(
            attempt_id=payload.attempt_id,
            binding_digest=payload.binding_digest,
            outcome=payload.outcome,
            actor_id=DATA_PLANE_INSTANCE_ID,
        )
    except db.ReleaseAuthorizationConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except db.ReleaseAuthorizationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _release_authorization_maintenance()
    return _release_authorization_api_response(result)


@app.get("/api/audit/verify")
def audit_verify(
    limit: int | None = Query(default=None, ge=1, le=10000),
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    return db.verify_audit_chain(limit=limit)


@app.get("/api/audit/anchors/status")
def audit_anchor_status(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    return runtime.audit_anchor_status()


@app.post("/api/audit/anchors/flush")
def audit_anchor_flush(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, Any]:
    return runtime.flush_audit_anchor()


@app.get("/api/runtime/metrics")
def runtime_metrics(
    _: AdminIdentity = Depends(require_role("auditor")),
) -> dict[str, int]:
    return runtime.metrics()


def _policy_status_document() -> dict[str, Any]:
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


@app.get("/api/policy")
def policy_status(
    _: AdminIdentity = Depends(require_role("auditor", "policy_author")),
) -> dict[str, Any]:
    return _policy_status_document()


def _upsert_credential(
    name: str, kind: str, secret: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    existing = next(
        (item for item in db.list_credentials() if item["name"] == name), None
    )
    if existing:
        return db.update_credential(
            existing["id"], {"kind": kind, "secret": secret, "metadata": metadata or {}}
        )
    return db.create_credential(name, kind, secret, metadata or {})


def _upsert_route(payload: dict[str, Any]) -> dict[str, Any]:
    existing = next(
        (item for item in db.list_routes() if item["name"] == payload["name"]), None
    )
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
        next_sequence = max(
            next_sequence, int(current_metadata.get("sequence") or 0) + 1
        )
        next_rollback_epoch = max(
            next_rollback_epoch,
            int(current_metadata.get("rollbackEpoch") or 0),
        )
    if high_water is not None:
        if high_water["policy_id"] != bundle["metadata"]["id"]:
            raise HTTPException(
                status_code=409,
                detail="demo policy id conflicts with persisted high-water state",
            )
        next_sequence = max(next_sequence, int(high_water["sequence"]) + 1)
        next_rollback_epoch = max(
            next_rollback_epoch, int(high_water["rollback_epoch"])
        )
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
                "policies": [
                    {
                        "type": "gmail_recent",
                        "days": 30,
                        "max_results": 10,
                        "cache_ttl_seconds": 1800,
                    }
                ],
            },
        ),
        _upsert_policy_route(
            "demo.approval.legacy",
            {
                **common,
                "name": "Demo approval gate",
                "match_path_prefix": "/approval",
                "policies": [
                    {
                        "type": "approval",
                        "ttl_seconds": 30,
                        "pending_ttl_seconds": 300,
                        "scope": "url",
                    }
                ],
            },
        ),
        _upsert_policy_route(
            "demo.npm.publish.jit",
            {
                **common,
                "name": "Demo NPM publish JIT",
                "match_path_prefix": "/npm",
                "policies": [
                    {
                        "type": "approval",
                        "ttl_seconds": 30,
                        "pending_ttl_seconds": 300,
                        "scope": "request_digest",
                    }
                ],
            },
        ),
        _upsert_policy_route(
            "demo.x.readonly",
            {
                **common,
                "name": "Demo X read-only",
                "match_path_prefix": "/2",
                "policies": [{"type": "x_read_only"}],
            },
        ),
        _upsert_policy_route(
            "demo.echo",
            {
                **common,
                "name": "Demo HTTPS bearer injection",
                "match_path_prefix": "/echo",
                "policies": [],
            },
        ),
        _upsert_policy_route(
            "demo.upload.stream",
            {
                **credentialless_stream,
                "name": "Demo streaming upload",
                "match_path_prefix": "/upload-bytes",
                "policies": [
                    {"type": "request_body_stream", "max_body_bytes": 1048576}
                ],
            },
        ),
        _upsert_policy_route(
            "demo.jsonl.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSONL streaming redaction",
                "match_path_prefix": "/jsonl-redact",
                "policies": [
                    {"type": "jsonl_stream_redaction", "max_body_bytes": 1048576}
                ],
            },
        ),
        _upsert_policy_route(
            "demo.json.array.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSON array streaming redaction",
                "match_path_prefix": "/json-array-redact",
                "policies": [
                    {"type": "json_array_stream_redaction", "max_body_bytes": 1048576}
                ],
            },
        ),
        _upsert_policy_route(
            "demo.json.sse.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo JSON SSE streaming redaction",
                "match_path_prefix": "/json-sse-redact",
                "policies": [
                    {"type": "json_sse_stream_redaction", "max_body_bytes": 1048576}
                ],
            },
        ),
        _upsert_policy_route(
            "demo.json.nested.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo nested JSON streaming redaction",
                "match_path_prefix": "/json-nested-redact",
                "policies": [
                    {"type": "json_nested_stream_redaction", "max_body_bytes": 1048576}
                ],
            },
        ),
        _upsert_policy_route(
            "demo.form.urlencoded.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo form-urlencoded streaming redaction",
                "match_path_prefix": "/form-redact",
                "policies": [
                    {
                        "type": "form_urlencoded_stream_redaction",
                        "max_body_bytes": 1048576,
                    }
                ],
            },
        ),
        _upsert_policy_route(
            "demo.csv.redact.stream",
            {
                **credentialless_stream,
                "name": "Demo CSV streaming redaction",
                "match_path_prefix": "/csv-redact",
                "policies": [
                    {"type": "csv_stream_redaction", "max_body_bytes": 1048576}
                ],
            },
        ),
    ]
    cleared_rate_limit_counters = db.clear_rate_limit_counters(
        ("demo.x.tweet.one_per_day",)
    )
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
    [hidden] { display: none !important; }
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
    :focus-visible { outline: 3px solid #2563eb; outline-offset: 2px; }
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
    .pending-oauth-list { display: grid; gap: 8px; margin-top: 12px; }
    .pending-oauth-item { border: 1px solid var(--line); border-radius: 6px; padding: 10px; background: var(--panel); min-width: 0; }
    .oauth-uncertain-item { border-color: #f59e0b; background: #fffbeb; }
    .oauth-revocation-confirm { display: flex; align-items: flex-start; gap: 8px; margin: 0; font-size: 12px; line-height: 1.4; }
    .oauth-revocation-confirm input { width: auto; flex: 0 0 auto; margin-top: 2px; }
    .setup-form-grid { display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 10px; }
    .setup-form-grid label { margin-top: 0; }
    .setup-actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
    .setup-checks { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; }
    .setup-check { min-width: 0; border: 1px solid var(--line); border-radius: 6px; padding: 10px; background: var(--panel); }
    .setup-check strong { display: block; margin: 5px 0 3px; font-size: 13px; overflow-wrap: anywhere; }
    .setup-check code { display: block; color: var(--muted); overflow-wrap: anywhere; }
    .setup-summary { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
    .filter-grid label { margin-top: 0; }
    .audit-summary { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 10px 0; }
    .attestation-summary { margin-bottom: 12px; }
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
      .setup-form-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
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
      .setup-section > .toolbar h2 { flex-basis: 100%; margin-bottom: 2px; }
      .setup-section > .section-kicker { margin: 8px 0 10px; }
      .setup-form-grid { grid-template-columns: minmax(0, 1fr); }
      .setup-actions button { width: 100%; white-space: normal; }
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
      .mobile-table,
      .mobile-table tbody,
      .mobile-table tr,
      .mobile-table td { display: block; width: 100%; }
      .mobile-table thead { display: none; }
      .mobile-table tr {
        border: 1px solid var(--line);
        border-radius: 6px;
        margin-bottom: 10px;
        overflow: hidden;
        background: var(--panel);
      }
      .mobile-table td {
        display: grid;
        grid-template-columns: minmax(72px, .3fr) minmax(0, 1fr);
        gap: 10px;
        overflow-wrap: anywhere;
      }
      .mobile-table td::before {
        content: attr(data-label);
        color: var(--muted);
        font-size: 11px;
        font-weight: 800;
        text-transform: uppercase;
      }
      .mobile-table .empty-row { border: 0; }
      .mobile-table .empty-row td { display: block; }
      .mobile-table .empty-row td::before { content: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        scroll-behavior: auto !important;
        transition-duration: .01ms !important;
        animation-duration: .01ms !important;
        animation-iteration-count: 1 !important;
      }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <header>
    <div class="brand"><div class="mark" aria-hidden="true"></div><h1>Serverware operator portal</h1></div>
    <div class="status">
      <span id="ca-status" class="pill warn" aria-label="Certificate authority status">CA pending</span>
      <span id="operator-auth-status" class="pill warn" aria-label="Operator authentication status">Signed out</span>
      <label class="sr-only" for="admin-token">Operator admin token or OIDC JWT</label>
      <input id="admin-token" class="token-field" type="password" placeholder="Admin token or OIDC JWT" autocomplete="off">
      <button id="operator-sign-in" class="secondary" type="button" onclick="runUiAction('Sign in', signInWithOIDC)" hidden>Sign in</button>
      <button id="operator-sign-out" class="secondary" type="button" onclick="runUiAction('Sign out', signOutOperator)" hidden>Sign out</button>
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
      <section class="setup-section">
        <div class="toolbar">
          <h2 style="margin-right:auto">Setup and Verify</h2>
          <span id="setup-configuration-status" class="pill warn">Configuration pending</span>
          <span id="setup-runtime-status" class="pill warn">Path not exercised</span>
          <span id="setup-hardware-status" class="pill warn">Hardware unverified</span>
        </div>
        <p class="section-kicker">Active assignment and independently reported runtime evidence</p>
        <div class="toolbar setup-session-controls">
          <div><label for="setup-session">Setup run</label><select id="setup-session"><option value="">New setup</option></select></div>
          <button id="setup-new-button" class="secondary" type="button" onclick="runUiAction('Create setup run', createSetupSession)">New run</button>
          <div><label for="setup-assignee">Next operator</label><input id="setup-assignee" maxlength="512" placeholder="user:operator"></div>
          <button id="setup-handoff-button" class="secondary" type="button" onclick="runUiAction('Hand off setup run', handoffSetupSession)" disabled>Hand off</button>
        </div>
        <form id="setup-form">
          <div class="setup-form-grid">
            <div><label for="setup-template">Restriction template</label><select id="setup-template" name="template"></select></div>
            <div><label for="setup-principal">Principal</label><select id="setup-principal" name="principalId"></select></div>
            <div><label for="setup-credential">Credential</label><select id="setup-credential" name="credentialId"></select></div>
            <div><label for="setup-route-id">Route ID</label><input id="setup-route-id" name="routeId" required maxlength="256"></div>
            <div id="setup-approvers-row" hidden><label for="setup-approvers">JIT approvers</label><input id="setup-approvers" name="approvers" maxlength="4096" placeholder="user:release-manager"></div>
          </div>
          <div class="setup-actions">
            <button id="setup-connect-button" class="secondary" type="button" onclick="runUiAction('Prepare provider login', prepareSetupProviderLogin)">Connect credential</button>
            <button id="setup-preview-button" class="secondary" type="button" onclick="runUiAction('Preview setup assignment', previewSetupAssignment)">Preview assignment</button>
            <button id="setup-stage-button" type="button" onclick="runUiAction('Stage setup assignment', stagePolicyCanary)" disabled>Stage assignment</button>
            <button id="setup-activate-button" type="button" onclick="runUiAction('Activate setup assignment', activatePolicyCanary)" disabled>Activate assignment</button>
            <button id="setup-enroll-button" class="secondary" type="button" onclick="runUiAction('Generate setup enrollment', generateSetupEnrollment)">Generate enrollment</button>
            <button id="setup-command-button" class="secondary" type="button" onclick="runUiAction('Download packet and copy verifier command', copyEnrollmentVerifier)" disabled>Copy verification command</button>
            <button id="setup-verify-button" class="secondary" type="submit">Verify server evidence</button>
          </div>
          <div class="setup-form-grid">
            <div><label for="setup-enrollment-receipt">Enrollment verifier receipt</label><input id="setup-enrollment-receipt" type="file" accept="application/json,.json"></div>
            <button id="setup-enrollment-receipt-button" class="secondary" type="button" onclick="runUiAction('Accept enrollment receipt', submitSetupEnrollmentReceipt)" disabled>Accept enrollment receipt</button>
            <button id="setup-challenge-button" class="secondary" type="button" onclick="runUiAction('Issue attestation challenge', issueSetupAttestationChallenge)" disabled>Issue challenge</button>
            <div><label for="setup-attestation-challenge">Attestation challenge</label><input id="setup-attestation-challenge" readonly></div>
            <button id="setup-copy-challenge-button" class="secondary" type="button" title="Copy attestation challenge" onclick="runUiAction('Copy attestation challenge', copySetupAttestationChallenge)" disabled>Copy challenge</button>
            <div><label for="setup-hardware-assurance">Hardware assurance</label><input id="setup-hardware-assurance" type="file" accept="application/json,.json"></div>
            <div><label for="setup-hardware-receipt">Hardware verifier receipt</label><input id="setup-hardware-receipt" type="file" accept="application/json,.json"></div>
            <div><label for="setup-proxy-statement">Proxy response statement</label><input id="setup-proxy-statement" type="file" accept="application/json,.json"></div>
            <button id="setup-hardware-button" class="secondary" type="button" onclick="runUiAction('Accept hardware verification', submitSetupHardwareVerification)" disabled>Accept hardware proof</button>
            <div><label for="setup-final-receipt">Off-host final receipt</label><input id="setup-final-receipt" type="file" accept="application/json,.json"></div>
            <button id="setup-final-button" type="button" onclick="runUiAction('Finalize attested setup', finalizeSetupAttestation)" disabled>Finalize attestation</button>
          </div>
        </form>
        <div id="setup-summary" class="setup-summary" role="status" aria-live="polite"></div>
        <div id="setup-checks" class="setup-checks"></div>
      </section>
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
          <div id="pending-oauth-section" class="pending-oauth-list" hidden>
            <h3>Verified accounts awaiting activation</h3>
            <div id="pending-oauth-credentials"></div>
          </div>
          <div id="oauth-uncertain-section" class="pending-oauth-list" hidden>
            <h3>Provider issuance requires review</h3>
            <p class="hint">The provider may have issued a grant, but Serverware could not durably confirm the result. Revoke the app in the provider account before clearing this record.</p>
            <div id="oauth-issuance-uncertainties"></div>
          </div>
        </section>
        <section>
          <h2>Agent Enrollment</h2>
          <form id="agent-enrollment-form">
            <label for="enrollment-principal">Principal</label>
            <select name="principalId" id="enrollment-principal"></select>
            <label for="enrollment-proxy-url">Proxy URL</label>
            <input id="enrollment-proxy-url" name="proxyUrl" value="http://localhost:8080">
            <label for="enrollment-control-plane-url">Control plane URL</label>
            <input id="enrollment-control-plane-url" name="controlPlaneUrl" value="http://localhost:3000" readonly>
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
          <button class="secondary" type="button" onclick="runUiAction('Download packet and copy verifier command', copyEnrollmentVerifier)">Download + copy verifier command</button>
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
        <table class="mobile-table">
          <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Evidence</th><th>Chain</th></tr></thead>
          <tbody id="audit-events"></tbody>
        </table>
      </section>
      <section class="attestation-section">
        <div class="toolbar">
          <h2 style="margin-right:auto">Attestation</h2>
          <button class="secondary" type="button" onclick="runUiAction('Refresh attestation', refreshAttestation)">Refresh evidence</button>
        </div>
        <div id="attestation-summary" class="attestation-summary" role="status" aria-live="polite"></div>
        <div id="attestation-evidence" class="review-grid"></div>
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
    let state = {credentials: [], pendingOAuthCredentials: [], oauthIssuanceUncertainties: [], routes: [], approvals: [], controlPlaneApprovals: [], logs: [], ca_ready: false, oauthProviders: [], policyPrincipals: [], enrollmentPacket: null, setupSessions: [], setupSession: null, setupChallenge: null, oauthSetupSessionId: null, setupVerification: null, approvalReview: null, activePolicy: null, policyCandidate: null, policyCanary: null, auditSearchResult: null, auditChain: null, attestation: null, authStatus: null};
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
    let csrfToken = null;
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
        requiredScopes: ['https://www.googleapis.com/auth/gmail.readonly'],
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
        requiredScopes: ['tweet.read', 'users.read'],
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
        requiredScopes: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
        injection: {type: 'bearer', field: 'access_token'},
        match: {scheme: 'https', host: 'api.x.com', port: 443, methods: ['POST'], paths: ['/2/tweets']},
        adapter: {type: 'x.v2', config: {mode: 'controlledWrite', blockWrites: false, response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['data.id', 'data.text'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['title', 'detail', 'type', 'status', 'errors.title', 'errors.detail', 'errors.type', 'errors.value'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
        constraints: [
          {id: 'x-only-tweet-create', type: 'operationPolicy', allowedOperations: ['tweets.write']},
          {id: 'x-one-post-per-day', type: 'rateLimit', max: 1, windowSeconds: 86400, store: 'shared', key: {scope: ['route', 'operation'], operationFields: ['providerAccount']}},
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
        adapter: {type: 'generic.rest', config: {request: {allowedHeaders: ['accept', 'content-type', 'idempotency-key', 'user-agent'], requiredHeaders: {'idempotency-key': {type: 'string', minLength: 1, maxLength: 255, pattern: '^[-A-Za-z0-9._:]{1,255}$'}}, allowedQueryKeys: [], bodyMode: 'formUrlencoded', maxBodyBytes: 16384, operation: {name: 'stripe.payment_intents.create', formFields: ['amount', 'currency', 'payment_method', 'confirm', 'metadata.agent_request_id']}}, response: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['id', 'object', 'amount', 'currency', 'status', 'payment_method', 'created'], allowedHeaders: [], error: {mode: 'json', maxBodyBytes: 65536, allowedFields: ['error.type', 'error.code', 'error.message', 'error.param'], allowedHeaders: ['retry-after'], onInvalid: 'block'}}}},
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

    function hasOperatorAuth() {
      return Boolean(adminToken() || state.authStatus?.authenticated);
    }

    function requireAdminToken() {
      if (hasOperatorAuth()) return true;
      $('admin-token').placeholder = 'Admin token or OIDC JWT required';
      $('admin-token').focus();
      setStatus('Sign in with OIDC or enter an operator token.', 'error');
      return false;
    }

    async function fetchAuthStatus() {
      const response = await fetch('/api/auth/status', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error(`Authentication status failed with ${response.status}`);
      state.authStatus = await response.json();
      renderAuthStatus();
      return state.authStatus;
    }

    function renderAuthStatus() {
      const authenticated = Boolean(state.authStatus?.authenticated);
      const tokenAuthenticated = Boolean(adminToken());
      const label = authenticated
        ? state.authStatus.userId
        : tokenAuthenticated
          ? 'Token session'
          : 'Signed out';
      $('operator-auth-status').textContent = label;
      $('operator-auth-status').className = authenticated || tokenAuthenticated ? 'pill good' : 'pill warn';
      $('operator-sign-in').hidden = authenticated || tokenAuthenticated || !state.authStatus?.oidcBrowserLoginConfigured;
      $('operator-sign-out').hidden = !authenticated;
      $('admin-token').hidden = authenticated;
    }

    async function signInWithOIDC() {
      const response = await fetch('/api/auth/oidc/start', {credentials: 'same-origin', cache: 'no-store'});
      const payload = await response.json();
      if (!response.ok) throw new ApiError(response.status, payload);
      window.location.assign(payload.authorizationUrl);
      return {pending: true};
    }

    async function signOutOperator() {
      await api('/api/auth/logout', {method: 'POST'});
      csrfToken = null;
      await fetchAuthStatus();
      render();
      return {signedOut: true};
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
        if (control.id.startsWith('setup-')) return;
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
      const bytes = new Uint8Array(value);
      let raw = '';
      for (let offset = 0; offset < bytes.length; offset += 0x8000) {
        raw += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
      }
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

    async function ensureCsrfToken() {
      if (adminToken()) return null;
      if (csrfToken) return csrfToken;
      const response = await fetch('/api/csrf', {
        headers: adminHeaders(),
        credentials: 'same-origin',
        cache: 'no-store'
      });
      const payload = await response.json();
      if (!response.ok) throw new ApiError(response.status, payload);
      csrfToken = payload.token;
      return csrfToken;
    }

    async function api(path, options = {}) {
      if (!requireAdminToken()) throw new Error('admin token required');
      const method = String(options.method || 'GET').toUpperCase();
      const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
      const csrf = unsafe ? await ensureCsrfToken() : null;
      const headers = {
        'Content-Type': 'application/json',
        ...adminHeaders(),
        ...(csrf ? {'X-Serverware-CSRF-Token': csrf} : {}),
        ...(options.headers || {})
      };
      const res = await fetch(path, {...options, method, headers, credentials: 'same-origin'});
      const text = res.status === 204 ? '' : await res.text();
      let payload = null;
      if (text) {
        try { payload = JSON.parse(text); } catch (_) { payload = {detail: text}; }
      }
      if (res.status === 401) {
        $('admin-token').value = '';
        $('admin-token').placeholder = 'Operator token rejected';
        sessionStorage.removeItem(tokenKey);
        csrfToken = null;
        state.authStatus = {...(state.authStatus || {}), authenticated: false, userId: null, roles: [], authMethod: null};
        renderAuthStatus();
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
        if (state.setupSession?.phase === 'credential_activated' && result?.canary?.id) {
          const bound = await api(`/api/setup/sessions/${encodeURIComponent(state.setupSession.id)}/canary`, {
            method: 'POST',
            body: JSON.stringify({expectedRevision: state.setupSession.revision, canaryId: result.canary.id})
          });
          rememberSetupSession(bound.session);
        }
      }
      if (mutation.kind === 'policy-canary-activate' && state.setupSession?.phase === 'policy_staged') {
        const bound = await api(`/api/setup/sessions/${encodeURIComponent(state.setupSession.id)}/policy`, {
          method: 'POST',
          body: JSON.stringify({expectedRevision: state.setupSession.revision})
        });
        rememberSetupSession(bound.session);
      }
      if (mutation.kind === 'webauthn-register-options') {
        await completePasskeyRegistration(result);
        return;
      }
      await refresh();
    }

    async function refresh() {
      if (refreshInFlight) return refreshInFlight;
      if (!hasOperatorAuth()) {
        render();
        return;
      }
      const controlState = captureControlState();
      refreshInFlight = (async () => {
        const retained = {
          enrollmentPacket: state.enrollmentPacket,
          setupSession: state.setupSession,
          setupChallenge: state.setupChallenge,
          oauthSetupSessionId: state.oauthSetupSessionId,
          setupVerification: state.setupVerification,
          approvalReview: state.approvalReview,
          policyCandidate: state.policyCandidate,
          auditSearchResult: state.auditSearchResult,
          auditChain: state.auditChain,
          authStatus: state.authStatus
        };
        const bootstrap = await api('/api/bootstrap');
        const [controlPlaneResult, policyResult, policyCanaryResult, attestationResult, setupSessionsResult] = await Promise.allSettled([
          api('/api/control-plane/approvals?limit=100'),
          api('/api/policy'),
          api('/api/policy/canary/status'),
          api(`/attestation?nonce=${encodeURIComponent(generateEnrollmentNonce())}`),
          api('/api/setup/sessions?limit=100')
        ]);
        const setupSessions = setupSessionsResult.status === 'fulfilled' ? setupSessionsResult.value.sessions || [] : [];
        const requestedSetupId = new URLSearchParams(window.location.search).get('setup');
        const selectedSetupId = requestedSetupId || retained.setupSession?.id || setupSessions[0]?.id || null;
        let setupSession = null;
        if (selectedSetupId) {
          try {
            setupSession = (await api(`/api/setup/sessions/${encodeURIComponent(selectedSetupId)}`)).session;
          } catch (error) {
            if (requestedSetupId && error.status !== 404 && error.status !== 403) throw error;
          }
        }
        state = {
          ...bootstrap,
          controlPlaneApprovals: controlPlaneResult.status === 'fulfilled' ? controlPlaneResult.value : [],
          activePolicy: policyResult.status === 'fulfilled' ? policyResult.value : null,
          policyCanary: policyCanaryResult.status === 'fulfilled' ? policyCanaryResult.value : null,
          attestation: attestationResult.status === 'fulfilled'
            ? attestationResult.value
            : {error: String(attestationResult.reason?.message || attestationResult.reason || 'Attestation unavailable')},
          setupSessions,
          setupSession,
          ...retained
        };
        state.setupSessions = setupSessions;
        state.setupSession = setupSession;
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
      const lifecycleStatus = item.lifecycle_status || 'active';
      const status = lifecycleStatus === 'revocation_failed'
        ? '<span class="pill bad">disconnect failed</span>'
        : lifecycleStatus === 'revocation_pending'
          ? '<span class="pill warn">disconnect pending</span>'
          : healthy
            ? '<span class="pill good">connected</span>'
            : metadata.refreshable === true
              ? '<span class="pill warn">refresh on use</span>'
              : '<span class="pill bad">reconnect</span>';
      const expiry = expires ? new Date(expires).toLocaleString() : 'unknown expiry';
      return `<div class="stack"><div class="toolbar">${status}${verified}</div><strong>${esc(account)}</strong><span class="muted">${esc(provider)} / ${esc(expiry)}</span>${scopes ? `<span class="muted">${esc(scopes)}</span>` : ''}</div>`;
    }

    function credentialActions(item) {
      const managedOAuth = item.kind === 'oauth2' && item.metadata?.oauth === true;
      if (!managedOAuth) return `<button class="danger" type="button" onclick="runUiAction('Delete credential', () => deleteCredential('${item.id}'))">Delete</button>`;
      if ((item.lifecycle_status || 'active') !== 'active') {
        return `<button class="danger" type="button" onclick="runUiAction('Retry OAuth disconnect', () => deleteCredential('${item.id}'))">Retry disconnect</button>`;
      }
      if (item.metadata?.provider_id === 'google') {
        return `<button class="danger" type="button" title="Google grants must be revoked before connecting again" onclick="runUiAction('Disconnect OAuth credential', () => deleteCredential('${item.id}'))">Disconnect</button>`;
      }
      return `<div class="toolbar"><button type="button" onclick="runUiAction('Reconnect OAuth credential', () => reconnectOAuthCredential('${item.id}'))">Reconnect</button><button class="danger" type="button" onclick="runUiAction('Disconnect OAuth credential', () => deleteCredential('${item.id}'))">Disconnect</button></div>`;
    }

    function renderPendingOAuthCredentials() {
      const items = state.pendingOAuthCredentials || [];
      $('pending-oauth-section').hidden = !items.length;
      $('pending-oauth-credentials').innerHTML = items.map((item) => {
        const review = item.review || {};
        const mine = item.requester_id === state.currentUserId;
        const canRevoke = mine || (state.currentUserRoles || []).includes('admin');
        const status = item.status || 'pending';
        const scopes = Array.isArray(review.scopes) ? review.scopes.join(', ') : '';
        let action = '';
        if (status === 'pending' && mine) {
          action = `<div class="toolbar"><button type="button" onclick="runUiAction('Activate verified OAuth account', () => activatePendingOAuthCredential('${item.id}'))">Request approval and activate</button><button class="danger" type="button" onclick="runUiAction('Cancel OAuth connection', () => cancelPendingOAuthCredential('${item.id}'))">Cancel</button></div>`;
        } else if (status === 'pending') {
          action = '<span class="pill warn">requester action required</span>';
        } else if (canRevoke && item.revocation_status !== 'revoked') {
          action = `<button class="secondary" type="button" onclick="runUiAction('Retry provider revocation', () => revokePendingOAuthCredential('${item.id}'))">Retry provider revocation</button>`;
        }
        return `<div class="pending-oauth-item stack">
          <div class="toolbar">${pill(status)}<strong>${esc(review.provider_account || 'Unknown account')}</strong></div>
          <span class="muted">${esc(review.provider || 'oauth')} / expires ${esc(item.expires_at)}</span>
          <code>${esc(review.provider_subject || '')}</code>
          ${scopes ? `<span class="muted">${esc(scopes)}</span>` : ''}
          <span class="muted">Requested by ${esc(item.requester_id)}</span>
          ${item.revocation_status ? `<span class="muted">Provider revocation: ${esc(item.revocation_status)}${item.revocation_error ? ` / ${esc(item.revocation_error)}` : ''}</span>` : ''}
          ${action}
        </div>`;
      }).join('');
    }

    function renderOAuthIssuanceUncertainties() {
      const items = state.oauthIssuanceUncertainties || [];
      $('oauth-uncertain-section').hidden = !items.length;
      $('oauth-issuance-uncertainties').innerHTML = items.map((item) => {
        const confirmId = `oauth-uncertain-confirm-${item.id}`;
        const noteId = `oauth-uncertain-note-${item.id}`;
        return `<div class="pending-oauth-item oauth-uncertain-item stack">
          <div class="toolbar"><span class="pill warn">issuance uncertain</span><strong>${esc(item.provider_id || 'OAuth provider')}</strong></div>
          <span class="muted">${esc(item.source || 'token exchange')} / detected ${esc(item.updated_at || item.created_at || '')}</span>
          <code>${esc(item.id)}</code>
          <span>${esc(item.last_error || 'The token exchange outcome could not be confirmed.')}</span>
          <span class="muted">Requested by ${esc(item.actor_id || 'unknown operator')}</span>
          <label class="oauth-revocation-confirm" for="${confirmId}"><input id="${confirmId}" type="checkbox">I confirmed the provider-side app grant was revoked.</label>
          <label for="${noteId}">Revocation evidence note</label>
          <input id="${noteId}" maxlength="2000" placeholder="Provider audit event, ticket, or verification details">
          <button class="danger" type="button" onclick="runUiAction('Resolve uncertain OAuth issuance', () => resolveOAuthIssuanceUncertainty('${item.id}'))">Confirm revocation and clear</button>
        </div>`;
      }).join('');
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

    function rememberSetupSession(session, {updateUrl = true} = {}) {
      if (state.setupSession?.id !== session?.id) state.setupChallenge = null;
      state.setupSession = session || null;
      if (session) {
        const existing = (state.setupSessions || []).filter((item) => item.id !== session.id);
        state.setupSessions = [session, ...existing];
      }
      if (updateUrl) {
        const url = new URL(window.location.href);
        if (session?.id) url.searchParams.set('setup', session.id);
        else url.searchParams.delete('setup');
        window.history.replaceState({}, '', url.pathname + url.search + url.hash);
      }
      return session;
    }

    function setupSessionMatchesSelection(session = state.setupSession, selection = currentSetupSelection()) {
      return Boolean(
        session
        && session.status === 'active'
        && (!session.templateId || session.templateId === selection.template)
        && (!session.principalId || session.principalId === selection.principalId)
        && (!session.routeId || session.routeId === selection.routeId)
        && (!session.credentialId || session.credentialId === selection.credentialId)
      );
    }

    async function createSetupSession() {
      const selection = currentSetupSelection();
      if (!selection.template || !selection.principalId || !selection.routeId) {
        throw new Error('Select a template, principal, and route before creating a setup run');
      }
      const activeRoute = (state.activePolicy?.bundle?.routes || []).find((item) => item.id === selection.routeId);
      if (!activeRoute) throw new Error('The selected route is not present in the active signed policy');
      const routePolicyDigest = await sha256CanonicalJson(activeRoute);
      const result = await api('/api/setup/sessions', {
        method: 'POST',
        body: JSON.stringify({
          templateId: selection.template,
          principalId: selection.principalId,
          routeId: selection.routeId,
          routePolicyDigest
        })
      });
      rememberSetupSession(result.session);
      state.setupVerification = null;
      renderSetupWorkflow();
      return result;
    }

    async function loadSetupSession(id) {
      if (!id) {
        rememberSetupSession(null);
        state.setupVerification = null;
        renderSetupWorkflow();
        return null;
      }
      const result = await api(`/api/setup/sessions/${encodeURIComponent(id)}`);
      rememberSetupSession(result.session);
      state.setupVerification = null;
      renderSetupWorkflow();
      return result.session;
    }

    async function handoffSetupSession() {
      const session = state.setupSession;
      const assigneeId = $('setup-assignee').value.trim();
      if (!session || !assigneeId) throw new Error('Select a setup run and enter the next operator');
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/handoff`, {
        method: 'POST',
        body: JSON.stringify({expectedRevision: session.revision, assigneeId})
      });
      rememberSetupSession(result.session);
      $('setup-assignee').value = '';
      renderSetupWorkflow();
      return result;
    }

    async function ensureSetupSession() {
      if (setupSessionMatchesSelection()) return state.setupSession;
      const result = await createSetupSession();
      return result.session;
    }

    async function bindSetupCredential() {
      let session = await ensureSetupSession();
      const selection = currentSetupSelection();
      if (session.credentialId) {
        if (session.credentialId !== selection.credentialId) throw new Error('This setup run is bound to another credential');
        return session;
      }
      if (session.phase !== 'created') throw new Error(`Setup run cannot bind a credential from ${session.phase}`);
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/credential`, {
        method: 'POST',
        body: JSON.stringify({expectedRevision: session.revision, credentialId: selection.credentialId})
      });
      session = rememberSetupSession(result.session);
      return session;
    }

    function currentSetupSelection() {
      return {
        template: $('setup-template').value,
        principalId: $('setup-principal').value,
        credentialId: $('setup-credential').value,
        routeId: $('setup-route-id').value.trim(),
        approvers: $('setup-approvers').value.trim()
      };
    }

    function canonicalJson(value) {
      if (value === null || typeof value !== 'object') return JSON.stringify(value);
      if (Array.isArray(value)) return '[' + value.map((item) => canonicalJson(item)).join(',') + ']';
      return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
    }

    async function sha256CanonicalJson(value) {
      const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson(value)));
      return 'sha256:' + Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
    }

    function setupAssignmentIsActive(selection = currentSetupSelection()) {
      const route = (state.activePolicy?.bundle?.routes || []).find((item) => item.id === selection.routeId);
      return Boolean(
        route
        && route.credentialRef === selection.credentialId
        && Array.isArray(route.principals)
        && (route.principals.includes(selection.principalId) || route.principals.includes('*'))
      );
    }

    function setupVerificationForSelection(selection = currentSetupSelection()) {
      const result = state.setupVerification;
      const assignment = result?.assignment;
      const session = state.setupSession;
      if (!assignment || !session) return null;
      const credential = (state.credentials || []).find((item) => item.id === selection.credentialId);
      return result.setupSessionId === session.id
        && result.setupRevision === session.revision
        && result.assignmentDigest === session.assignmentDigest
        && assignment.principalId === selection.principalId
        && assignment.routeId === selection.routeId
        && assignment.credentialId === selection.credentialId
        && assignment.policyHash === state.activePolicy?.policy_hash
        && assignment.credentialVersion === credential?.credential_version
        && assignment.routePolicyDigest === session.routePolicyDigest
        && session.enrollmentSessionId === state.enrollmentPacket?.ca?.installSession?.id
        ? result
        : null;
    }

    function setupStatusPill(targetId, passed, passLabel, pendingLabel) {
      const target = $(targetId);
      target.textContent = passed ? passLabel : pendingLabel;
      target.className = passed ? 'pill good' : 'pill warn';
    }

    function renderSetupWorkflow(controlState = {}) {
      const setupSession = state.setupSession;
      const setupSessions = state.setupSessions || [];
      $('setup-session').innerHTML = '<option value="">New setup</option>' + setupSessions.map((item) => `<option value="${esc(item.id)}">${esc(item.phase)} / ${esc(item.routeId || item.id)}</option>`).join('');
      $('setup-session').value = setupSession?.id || '';
      $('setup-handoff-button').disabled = !setupSession || setupSession.status !== 'active' || !setupSession.ownerId;

      const savedTemplate = setupSession?.templateId || controlState['id:setup-template']?.value || $('setup-template').value;
      $('setup-template').innerHTML = Object.entries(policyTemplates).map(([key, item]) => `<option value="${esc(key)}">${esc(item.label)}</option>`).join('');
      $('setup-template').value = policyTemplates[savedTemplate] ? savedTemplate : Object.keys(policyTemplates)[0] || '';
      const template = policyTemplates[$('setup-template').value];

      const savedPrincipal = setupSession?.principalId || controlState['id:setup-principal']?.value || $('setup-principal').value;
      $('setup-principal').innerHTML = (state.policyPrincipals || []).map((item) => `<option value="${esc(item.id)}">${esc(item.id)}</option>`).join('');
      if (Array.from($('setup-principal').options).some((item) => item.value === savedPrincipal)) $('setup-principal').value = savedPrincipal;

      const savedCredential = setupSession?.credentialId || controlState['id:setup-credential']?.value || $('setup-credential').value;
      const credentials = template ? policyCredentialOptions(template) : [];
      $('setup-credential').innerHTML = credentials.map((item) => `<option value="${esc(item.id)}" ${item.compatible ? '' : 'disabled'} title="${esc(item.reason)}">${esc(item.label)}${item.compatible ? '' : ' (not compatible)'}</option>`).join('');
      const selectedCredential = credentials.find((item) => item.id === savedCredential && item.compatible) || credentials.find((item) => item.compatible);
      $('setup-credential').value = selectedCredential?.id || '';
      $('setup-credential').disabled = !selectedCredential;

      const savedRoute = setupSession?.routeId || controlState['id:setup-route-id']?.value || $('setup-route-id').value.trim();
      $('setup-route-id').value = savedRoute || template?.routeId || '';
      const savedApprovers = controlState['id:setup-approvers']?.value;
      if (savedApprovers != null) $('setup-approvers').value = savedApprovers;
      $('setup-approvers-row').hidden = !template?.jit;
      $('setup-approvers').required = Boolean(template?.jit);
      const bindingsLocked = Boolean(setupSession && setupSession.phase !== 'created');
      $('setup-template').disabled = bindingsLocked;
      $('setup-principal').disabled = bindingsLocked;
      $('setup-route-id').readOnly = bindingsLocked;
      $('setup-credential').disabled = Boolean(setupSession?.credentialId);

      const selection = currentSetupSelection();
      const verification = setupVerificationForSelection(selection);
      const candidateReady = Boolean(
        state.policyCandidate?.report?.dryRun?.passed === true
        && state.policyCandidate.routeId === selection.routeId
        && state.policyCandidate.principalId === selection.principalId
        && state.policyCandidate.credentialRef === selection.credentialId
        && state.policyCandidate.templateId === selection.template
      );
      const staged = Boolean(
        candidateReady
        && state.policyCanary?.canary?.status === 'running'
        && state.policyCanary.canary.candidatePolicyHash === state.policyCandidate?.report?.candidate?.policyHash
      );
      const active = setupAssignmentIsActive(selection);
      const packetMatches = Boolean(
        state.enrollmentPacket?.principalId === selection.principalId
        && state.enrollmentPacket?.pinning?.policyHash === state.activePolicy?.policy_hash
        && Number(state.enrollmentPacket?.expiresAtEpochMs || 0) > Date.now()
        && (state.enrollmentPacket?.allowedRoutes || []).some((item) => item.id === selection.routeId && item.credentialRef === selection.credentialId)
      );
      const oauthProvider = (state.oauthProviders || []).find((item) => item.id === template?.provider);
      $('setup-connect-button').textContent = oauthProvider ? 'Connect credential' : 'Add credential';
      $('setup-connect-button').disabled = Boolean(setupSession?.credentialId) || Boolean(oauthProvider && !oauthProvider.configured);
      $('setup-preview-button').disabled = !selection.principalId || !selection.credentialId || !selection.routeId || (Boolean(template?.jit) && !selection.approvers);
      $('setup-stage-button').disabled = !candidateReady || setupSession?.phase !== 'credential_activated';
      $('setup-activate-button').disabled = !staged || setupSession?.phase !== 'policy_staged';
      $('setup-enroll-button').disabled = !active || setupSession?.phase !== 'policy_activated';
      $('setup-command-button').disabled = !packetMatches;
      $('setup-verify-button').disabled = !setupSession || !['enrollment_issued', 'ca_installed', 'canaries_verified', 'runtime_verified', 'hardware_verified'].includes(setupSession.phase);
      $('setup-enrollment-receipt-button').disabled = setupSession?.phase !== 'enrollment_issued';
      $('setup-challenge-button').disabled = setupSession?.phase !== 'runtime_verified';
      $('setup-challenge-button').textContent = setupSession?.attestationChallengeDigest ? 'Get challenge' : 'Issue challenge';
      $('setup-hardware-button').disabled = setupSession?.phase !== 'runtime_verified' || !setupSession?.attestationChallengeDigest;
      $('setup-final-button').disabled = !['hardware_verified', 'completion_pending_audit'].includes(setupSession?.phase);
      $('setup-attestation-challenge').value = state.setupChallenge && state.setupChallenge.setupSessionId === setupSession?.id ? state.setupChallenge.value : '';
      $('setup-copy-challenge-button').disabled = !state.setupChallenge?.value || state.setupChallenge.setupSessionId !== setupSession?.id;

      setupStatusPill('setup-configuration-status', verification?.configurationReady === true, 'Configuration ready', active ? 'Evidence pending' : 'Configuration pending');
      setupStatusPill('setup-runtime-status', verification?.runtimeVerified === true, 'Path exercised', 'Path not exercised');
      const hardwareVerified = ['hardware_verified', 'completion_pending_audit', 'complete'].includes(setupSession?.phase);
      setupStatusPill('setup-hardware-status', hardwareVerified, setupSession?.phase === 'complete' ? 'Attestation complete' : 'Hardware verified', 'Hardware unverified');

      const summary = $('setup-summary');
      const checks = $('setup-checks');
      if (!verification) {
        summary.innerHTML = `<span class="pill ${setupSession ? 'warn' : 'bad'}">${esc(setupSession?.phase || 'No setup run')}</span><span class="muted">${setupSession ? `Revision ${setupSession.revision}; assigned to ${esc(setupSession.currentAssigneeId || setupSession.ownerId)}` : 'Create a durable setup run before connecting a credential.'}</span>`;
        checks.replaceChildren();
        return;
      }
      const actionLabels = {
        repair_active_assignment: 'Repair active assignment',
        verify_enrollment_and_install_ca: 'Install the verified CA',
        enroll_agent_and_exercise_route: 'Exercise the enrolled route',
        approve_and_retry_exact_request: 'Approve and retry the request',
        wait_for_validated_response_evidence: 'Waiting for validated response',
        verify_on_hardware_backed_deployment: 'Independent hardware proof required',
        verified: 'Verified'
      };
      summary.innerHTML = `<span class="pill ${verification.fullyVerified ? 'good' : verification.configurationReady ? 'warn' : 'bad'}">${esc(actionLabels[verification.nextAction] || 'Review verification checks')}</span><code>${esc(verification.assignmentDigest)}</code>`;
      checks.innerHTML = (verification.checks || []).map((item) => `
        <div class="setup-check">
          <span class="pill ${item.status === 'pass' ? 'good' : item.status === 'pending' ? 'warn' : 'bad'}">${esc(item.status)}</span>
          <strong>${esc(item.id)}</strong>
          <div>${esc(item.summary)}</div>
          ${item.evidence?.createdAt ? `<code>${esc(item.evidence.createdAt)}</code>` : ''}
        </div>`).join('');
    }

    function renderPolicyPrincipalOptions() {
      const options = (state.policyPrincipals || []).map((item) => `<option value="${esc(item.id)}">${esc(item.id)}</option>`).join('');
      $('enrollment-principal').innerHTML = (state.policyPrincipals || []).map((item) => `<option value="${esc(item.id)}">${esc(item.id)} (${esc(item.routeCount)} routes)</option>`).join('');
      $('enrollment-control-plane-url').value = state.publicUrl || '';
      $('policy-principal').innerHTML = options;
    }

    function render(controlState = captureControlState()) {
      renderAuthStatus();
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
      renderSetupWorkflow(controlState);
      renderEnrollmentOutput();
      renderPendingOAuthCredentials();
      renderOAuthIssuanceUncertainties();
      $('credentials').innerHTML = state.credentials.map((item) => `
        <tr>
          <td><strong>${esc(item.name)}</strong><br><code>${esc(item.id)}</code></td>
          <td>${esc(item.kind)}</td>
          <td>${credentialAccountStatus(item)}</td>
          <td><code class="json">${json(item.metadata)}</code></td>
          <td>${credentialActions(item)}</td>
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
      renderAttestation();

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
        'credential_type', 'provider', 'provider_subject', 'provider_account', 'credential_name', 'scopes',
        'metadata_keys', 'expires_at_epoch_ms', 'x_app_id', 'name', 'kind',
        'policy_id', 'previous_policy_hash', 'candidate_policy_hash', 'previous_sequence', 'new_sequence',
        'previous_rollback_epoch', 'new_rollback_epoch', 'diff', 'dry_run', 'route_id', 'changed_fields',
        'match_host', 'match_path_prefix', 'credential_id', 'enabled', 'subject_id', 'roles', 'reason',
        'work_id', 'confirmed_provider_revocation', 'source', 'note'
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
        const approvalBlockAttributes = approvalBlockReason ? `disabled aria-disabled="true" aria-describedby="${approvalBlockReasonId}"` : '';
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
          <td data-label="Time"><code>${esc(item.created_at)}</code></td>
          <td data-label="Event"><strong>${esc(item.event_type)}</strong><br><code>${esc(item.id)}</code></td>
          <td data-label="Actor"><code>${esc(item.actor_type || '')}:${esc(item.actor_id || '')}</code></td>
          <td data-label="Evidence"><code class="json">${json(redactAuditEvidence(item.event || {}))}</code></td>
          <td data-label="Chain"><code title="${esc(item.event_hash || '')}">${esc(String(item.event_hash || '').slice(0, 18))}${item.event_hash ? '...' : ''}</code></td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="5" class="muted">No matching audit events</td></tr>';
    }

    function renderAttestation() {
      const document = state.attestation;
      if (!document || document.error) {
        $('attestation-summary').innerHTML = `<span class="pill bad">unavailable</span><span class="muted">${esc(document?.error || 'Evidence has not been loaded')}</span>`;
        $('attestation-evidence').innerHTML = '';
        return;
      }
      const assurance = document.assurance || {};
      const hardwareClaimed = assurance.hardware_proof === true
        && assurance.workload_custody_proven === true
        && assurance.tls_peer_binding_proven === true;
      $('attestation-summary').innerHTML = hardwareClaimed
        ? `<span class="pill warn">server claims hardware</span><strong>${esc(assurance.class || 'hardware-backed')}</strong><span class="muted">Independent verifier receipt required.</span>`
        : `<span class="pill bad">not hardware verified</span><strong>${esc(assurance.class || 'unclassified')}</strong><span class="muted">${esc(assurance.reason || 'External verification is required.')}</span>`;
      const fields = [
        ['TEE platform', document.tee_platform],
        ['Fact origin', assurance.fact_origin],
        ['Nonce', document.nonce],
        ['Policy digest', document.policy_bundle_digest],
        ['Policy sequence', document.policy_sequence],
        ['Rollback epoch', document.rollback_epoch],
        ['Runtime manifest', document.runtime_manifest_digest],
        ['Source tree', document.source_tree_digest],
        ['Data-plane binary', document.data_plane_binary_digest],
        ['Provenance', document.provenance_digest],
        ['Response key', document.response_signing_key_id],
        ['TLS exporter', document.tls_exporter_binding || 'not bound']
      ];
      $('attestation-evidence').innerHTML = fields.map(([label, value]) => `
        <div class="review-field"><span>${esc(label)}</span><code>${esc(value ?? 'not published')}</code></div>
      `).join('');
    }

    async function refreshAttestation() {
      try {
        state.attestation = await api(`/attestation?nonce=${encodeURIComponent(generateEnrollmentNonce())}`);
      } catch (error) {
        state.attestation = {error: error.message};
        throw error;
      } finally {
        renderAttestation();
      }
      return state.attestation;
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
        const grantedScopes = new Set(oauthCredentialGrantedScopes(credential));
        const missingScopes = (template.requiredScopes || []).filter((scope) => !grantedScopes.has(scope));
        if (missingScopes.length) {
          throw new Error(`OAuth credential ${credential.id} is missing required scopes: ${missingScopes.join(', ')}`);
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
      return {bundle, dryRun, basePolicyHash: state.activePolicy.policy_hash, routeId, principalId, credentialRef, templateId: form.get('template')};
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
        if (state.oauthSetupSessionId) {
          const setupSession = state.setupSession?.id === state.oauthSetupSessionId
            ? state.setupSession
            : (await api(`/api/setup/sessions/${encodeURIComponent(state.oauthSetupSessionId)}`)).session;
          if (setupSession.phase !== 'created') throw new Error(`Setup run cannot start OAuth from ${setupSession.phase}`);
          body.setupSessionId = setupSession.id;
          body.setupRevision = setupSession.revision;
        }
        saveOAuthDraft();
        const mutation = {kind: 'oauth-start', label: `Connect ${provider.displayName}`, persist: true, path: '/api/oauth/start', method: 'POST', body};
        const completed = await runControlPlaneMutation(mutation);
        if (completed.pending) $('oauth-status').textContent = `Waiting for approval ${completed.approval.approvalId}.`;
        else await finishMutation(completed.mutation, completed.result);
        return completed;
      });
    });

    function focusPortalForm(formId) {
      const form = $(formId);
      const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      form.scrollIntoView({behavior: reducedMotion ? 'auto' : 'smooth', block: 'start'});
      const first = form.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled])');
      if (first) first.focus({preventScroll: true});
    }

    async function prepareSetupProviderLogin() {
      const selection = currentSetupSelection();
      const template = policyTemplates[selection.template];
      if (!template) throw new Error('Select a restriction template');
      const setupSession = await ensureSetupSession();
      const provider = (state.oauthProviders || []).find((item) => item.id === template.provider);
      if (!provider) {
        $('credential-name').value = `${template.label} credential`;
        $('credential-kind').value = 'bearer';
        syncCredentialKindFields(true);
        focusPortalForm('credential-form');
        return {mode: 'static-credential'};
      }
      if (!provider.configured) throw new Error(`${provider.displayName} OAuth is not configured`);
      $('oauth-provider').value = provider.id;
      const scopes = Array.from(new Set([...(provider.defaultScopes || []), ...(template.requiredScopes || [])]));
      $('oauth-scopes').value = scopes.join('\n');
      if (!$('oauth-credential-name').value.trim()) $('oauth-credential-name').value = `${template.label} credential`;
      renderOAuthDefaults(false);
      state.oauthSetupSessionId = setupSession.id;
      saveOAuthDraft();
      focusPortalForm('oauth-form');
      return {mode: 'oauth', provider: provider.id, scopes};
    }

    async function previewSetupAssignment() {
      const selection = currentSetupSelection();
      const template = policyTemplates[selection.template];
      if (!template) throw new Error('Select a restriction template');
      await bindSetupCredential();
      $('policy-template').value = selection.template;
      syncPolicyTemplateEditor(true);
      $('policy-route-id').value = selection.routeId;
      $('policy-principal').value = selection.principalId;
      renderPolicyCredentialOptions(selection.credentialId);
      if ($('policy-credential').value !== selection.credentialId) {
        throw new Error('The selected credential is not compatible with this restriction template');
      }
      if (template.jit) $('policy-approvers').value = selection.approvers;
      const result = await previewPolicyCandidate();
      renderSetupWorkflow();
      return result;
    }

    async function generateEnrollmentFromForm() {
      const form = new FormData($('agent-enrollment-form'));
      const proxyEgressCidrs = parseProxyEgressCidrs(form.get('proxyEgressCidrs'));
      const enrollmentNonce = generateEnrollmentNonce();
      state.enrollmentPacket = await api('/api/agents/enrollment', {method: 'POST', body: JSON.stringify({
        principalId: form.get('principalId'), proxyUrl: form.get('proxyUrl'), proxyEgressCidrs,
        namespace: form.get('namespace') || 'serverware-agents', caMountPath: form.get('caMountPath') || '/etc/serverware/serverware-ca.pem', podSelector: JSON.parse(form.get('podSelector') || '{}'),
        nonce: enrollmentNonce, ttlSeconds: 300
      })});
      renderEnrollmentOutput();
      renderSetupWorkflow();
      return state.enrollmentPacket;
    }

    async function generateSetupEnrollment() {
      const selection = currentSetupSelection();
      if (!setupAssignmentIsActive(selection)) throw new Error('Activate the exact principal, route, and credential assignment first');
      if (state.setupSession?.phase !== 'policy_activated') throw new Error('The durable setup run has not recorded policy activation');
      $('enrollment-principal').value = selection.principalId;
      const packet = await generateEnrollmentFromForm();
      const enrollmentSessionId = packet?.ca?.installSession?.id;
      if (!enrollmentSessionId || !packet?.nonce) throw new Error('Enrollment packet is missing its setup bindings');
      const bound = await api(`/api/setup/sessions/${encodeURIComponent(state.setupSession.id)}/enrollment`, {
        method: 'POST',
        body: JSON.stringify({
          expectedRevision: state.setupSession.revision,
          enrollmentSessionId,
          verifierNonce: packet.nonce
        })
      });
      rememberSetupSession(bound.session);
      renderSetupWorkflow();
      return packet;
    }

    async function verifySetupEvidence() {
      const session = state.setupSession;
      if (!session) throw new Error('Select a durable setup run');
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/verify`, {
        method: 'POST',
        body: JSON.stringify({
          expectedRevision: session.revision,
          nonce: generateEnrollmentNonce()
        })
      });
      rememberSetupSession(result.session);
      state.setupVerification = result.verification;
      renderSetupWorkflow();
      return result;
    }

    async function readSetupArtifact(inputId, maximumBytes, label) {
      const file = $(inputId).files?.[0];
      if (!file) throw new Error(`Select the ${label} JSON file`);
      if (file.size < 1 || file.size > maximumBytes) throw new Error(`${label} must be between 1 and ${maximumBytes} bytes`);
      return bytesToB64(await file.arrayBuffer());
    }

    async function submitSetupEnrollmentReceipt() {
      const session = state.setupSession;
      if (!session || session.phase !== 'enrollment_issued') throw new Error('This setup run is not awaiting enrollment verification');
      const receipt = await readSetupArtifact('setup-enrollment-receipt', 65536, 'enrollment verifier receipt');
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/enrollment-receipt`, {
        method: 'POST',
        body: JSON.stringify({expectedRevision: session.revision, receipt})
      });
      rememberSetupSession(result.session);
      state.setupVerification = null;
      renderSetupWorkflow();
      return result;
    }

    async function issueSetupAttestationChallenge() {
      const session = state.setupSession;
      if (!session || session.phase !== 'runtime_verified') throw new Error('Verify runtime evidence before issuing a hardware challenge');
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/attestation-challenge`, {
        method: 'POST',
        body: JSON.stringify({expectedRevision: session.revision})
      });
      rememberSetupSession(result.session);
      state.setupChallenge = {...result.challenge, setupSessionId: result.session.id};
      renderSetupWorkflow();
      return result;
    }

    async function copySetupAttestationChallenge() {
      const challenge = state.setupChallenge;
      if (!challenge || challenge.setupSessionId !== state.setupSession?.id) throw new Error('Issue a challenge in this browser first');
      await navigator.clipboard.writeText(challenge.value);
      return {sha256: challenge.sha256};
    }

    async function submitSetupHardwareVerification() {
      const session = state.setupSession;
      if (!session || session.phase !== 'runtime_verified' || !session.attestationChallengeDigest) throw new Error('This setup run is not awaiting hardware verification');
      const hardwareAssurance = await readSetupArtifact('setup-hardware-assurance', 524288, 'hardware assurance');
      const receipt = await readSetupArtifact('setup-hardware-receipt', 65536, 'hardware verifier receipt');
      const proxyServerStatement = await readSetupArtifact('setup-proxy-statement', 131072, 'proxy response statement');
      const result = await api(`/api/setup/sessions/${encodeURIComponent(session.id)}/hardware-verification`, {
        method: 'POST',
        body: JSON.stringify({
          expectedRevision: session.revision,
          hardwareAssurance,
          proxyServerStatement,
          receipt
        })
      });
      rememberSetupSession(result.session);
      state.setupChallenge = null;
      state.setupVerification = null;
      renderSetupWorkflow();
      return result;
    }

    async function finalizeSetupAttestation() {
      const session = state.setupSession;
      if (!session || !['hardware_verified', 'completion_pending_audit'].includes(session.phase)) throw new Error('This setup run is not awaiting final attestation');
      const receipt = await readSetupArtifact('setup-final-receipt', 65536, 'off-host final receipt');
      const mutation = {
        kind: 'setup-attestation-finalize',
        label: 'Finalize attested setup',
        persist: true,
        path: `/api/setup/sessions/${encodeURIComponent(session.id)}/final-receipt`,
        method: 'POST',
        body: {expectedRevision: session.revision, receipt}
      };
      const completed = await runControlPlaneMutation(mutation);
      if (completed.pending) return completed;
      await finishMutation(completed.mutation, completed.result);
      return completed.result;
    }

    $('setup-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Verify setup evidence', verifySetupEvidence);
    });
    $('setup-session').addEventListener('change', (event) => {
      runUiAction('Load setup run', () => loadSetupSession(event.target.value));
    });
    $('setup-template').addEventListener('change', () => {
      state.setupVerification = null;
      const template = policyTemplates[$('setup-template').value];
      $('setup-route-id').value = template?.routeId || '';
      $('setup-approvers').value = '';
      renderSetupWorkflow();
    });
    for (const id of ['setup-principal', 'setup-credential', 'setup-route-id', 'setup-approvers']) {
      $(id).addEventListener(id === 'setup-route-id' || id === 'setup-approvers' ? 'input' : 'change', () => {
        state.setupVerification = null;
        renderSetupWorkflow();
      });
    }

    $('agent-enrollment-form').addEventListener('submit', (event) => {
      event.preventDefault();
      runUiAction('Generate enrollment', generateEnrollmentFromForm);
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

    function enrollmentFilename(packet) {
      const principal = String(packet?.principalId || 'agent').replace(/[^a-zA-Z0-9_.-]+/g, '-');
      return `serverware-enrollment-${principal}.json`;
    }

    function enrollmentPacketText(packet) {
      return JSON.stringify(packet, null, 2) + '\n';
    }

    function downloadEnrollment(packetText = null) {
      if (!state.enrollmentPacket) return;
      const filename = enrollmentFilename(state.enrollmentPacket);
      const blob = new Blob([packetText || enrollmentPacketText(state.enrollmentPacket)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      return filename;
    }

    async function deleteCredential(id) {
      const item = state.credentials.find((candidate) => candidate.id === id);
      const managedOAuth = item?.kind === 'oauth2' && item?.metadata?.oauth === true;
      const prompt = managedOAuth
        ? `Disconnect credential ${id} and revoke its provider grant? Agents using it will fail closed.`
        : `Delete credential ${id}? Agents using it will fail closed.`;
      if (!window.confirm(prompt)) return cancelledAction('Credential deletion');
      const mutation = {kind: 'credential-delete', label: `Delete credential ${id}`, persist: false, path: `/api/credentials/${id}`, method: 'DELETE', body: {}};
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }
    async function reconnectOAuthCredential(id) {
      const item = state.credentials.find((candidate) => candidate.id === id);
      if (!item || item.kind !== 'oauth2' || item.metadata?.oauth !== true) throw new Error('Managed OAuth credential is unavailable');
      if ((item.lifecycle_status || 'active') !== 'active') throw new Error('Complete provider revocation before reconnecting this credential');
      if (item.metadata?.provider_id === 'google') throw new Error('Disconnect the Google credential before connecting the account again');
      const body = {
        provider: item.metadata.provider_id,
        credentialId: item.id,
        credentialName: item.name,
        scopes: Array.isArray(item.metadata.scopes) ? item.metadata.scopes : null
      };
      const mutation = {kind: 'oauth-start', label: `Reconnect ${item.name}`, persist: true, path: '/api/oauth/start', method: 'POST', body};
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }
    async function activatePendingOAuthCredential(id) {
      const item = (state.pendingOAuthCredentials || []).find((candidate) => candidate.id === id);
      if (!item) throw new Error('Pending OAuth credential is no longer available');
      if (item.requester_id !== state.currentUserId) throw new Error('Only the OAuth requester can activate this account');
      const account = item.review?.provider_account || id;
      const setupSession = (state.setupSessions || []).find((session) => session.oauthPendingCredentialId === id)
        || (state.setupSession?.oauthPendingCredentialId === id ? state.setupSession : null);
      const mutation = {
        kind: 'oauth-activate',
        label: `Activate verified OAuth account ${account}`,
        persist: true,
        path: `/api/oauth/pending/${id}/activate`,
        method: 'POST',
        body: setupSession ? {setupSessionId: setupSession.id, setupRevision: setupSession.revision} : {}
      };
      const completed = await runControlPlaneMutation(mutation);
      if (!completed.pending) await finishMutation(completed.mutation, completed.result);
      return completed;
    }
    async function cancelPendingOAuthCredential(id) {
      if (!window.confirm('Cancel this OAuth connection attempt and revoke its provider grant?')) return cancelledAction('OAuth connection cancellation');
      const result = await api(`/api/oauth/pending/${id}`, {method: 'DELETE'});
      await refresh();
      if (result.revocation?.ok !== true) throw new Error('Connection cancelled, but provider revocation must be retried');
      return result;
    }
    async function revokePendingOAuthCredential(id) {
      try {
        return await api(`/api/oauth/pending/${id}/revoke`, {method: 'POST'});
      } finally {
        await refresh();
      }
    }
    async function resolveOAuthIssuanceUncertainty(id) {
      const item = (state.oauthIssuanceUncertainties || []).find((candidate) => candidate.id === id);
      if (!item) throw new Error('OAuth issuance uncertainty is no longer available');
      const confirmed = $(`oauth-uncertain-confirm-${id}`)?.checked === true;
      const note = $(`oauth-uncertain-note-${id}`)?.value.trim() || '';
      if (!confirmed) throw new Error('Confirm provider-side revocation before clearing this uncertainty');
      if (!note) throw new Error('Record evidence of the provider-side revocation');
      const mutation = {
        kind: 'oauth-issuance-uncertainty-resolve',
        label: `Resolve uncertain ${item.provider_id || 'OAuth'} issuance`,
        persist: true,
        path: `/api/oauth/issuance-uncertainties/${id}/resolve`,
        method: 'POST',
        body: {confirmedProviderRevocation: true, note}
      };
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
        const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true;
        $('approval-review').scrollIntoView({behavior: reducedMotion ? 'auto' : 'smooth', block: 'start'});
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
          <td data-label="Status">${pill(item.status)}</td>
          <td data-label="Requested"><code>${esc(item.requested_at || '')}</code></td>
          <td data-label="Decision note">${esc(item.decision_note || '')}</td>
          <td data-label="Request digest"><code>${esc(item.request_digest || '')}</code></td>
        </tr>`).join('') || '<tr class="empty-row"><td colspan="4" class="muted">No similar approvals</td></tr>';
      target.innerHTML = `
        <h3>Approval review</h3>
        <div class="review-grid">
          <div class="review-field"><span>Approval</span><code>${esc(review.id)}</code>${pill(review.status)}</div>
          <div class="review-field"><span>Expires</span><code>${esc(review.expires_at || '')}</code></div>
          <div class="review-field"><span>Principal</span><code>${esc(review.principal_id)}</code></div>
          <div class="review-field"><span>Source</span><code class="json">${json(review.source_identity)}</code></div>
          <div class="review-field"><span>Route</span><code>${esc(review.route_id)}</code></div>
          <div class="review-field"><span>Credential</span><code>${esc(review.credential_ref)}@${esc(review.credential_version)}</code></div>
          <div class="review-field"><span>Policy</span><code>${esc(review.policy_hash)}</code></div>
          <div class="review-field"><span>Request</span><code>${esc(review.method)} ${esc(review.url)}</code></div>
          <div class="review-field"><span>Body hash</span><code>${esc(review.body_hash || '')}</code></div>
          <div class="review-field"><span>Request digest</span><code>${esc(retry.request_digest || '')}</code></div>
          <div class="review-field"><span>Operation digest</span><code>${esc(retry.operation_digest || '')}</code></div>
          <div class="review-field"><span>Review digest</span><code>${esc(review.review_digest || '')}</code></div>
          <div class="review-field"><span>Review receipt expires</span><code>${esc(review.review_receipt?.expires_at || 'not approvable')}</code></div>
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
          <table class="mobile-table">
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
      const reviewReceiptId = state.approvalReview?.review_receipt?.id;
      if (!reviewReceiptId) {
        await loadApprovalReview(id);
        setStatus(`Review receipt refreshed for approval ${id}. Inspect it before approving.`, 'pending');
        return {pending: true, reviewLoaded: true};
      }
      const options = await api(`/api/approvals/${id}/webauthn/options`, {
        method: 'POST',
        body: JSON.stringify({reviewReceiptId})
      });
      let body = {reviewReceiptId};
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
      const packetText = enrollmentPacketText(packet);
      const packetFilename = downloadEnrollment(packetText);
      const packetDigestBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(packetText));
      const packetSha256 = 'sha256:' + Array.from(new Uint8Array(packetDigestBytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
      const setupSession = state.setupSession;
      let receiptTrust = null;
      if (setupSession?.enrollmentSessionId) {
        try {
          receiptTrust = await api('/api/setup/receipt-trust');
        } catch (error) {
          if (error.status !== 503) throw error;
        }
      }
      const command = [
        'set -euo pipefail',
        'umask 077',
        'ENROLLMENT_PACKET="${SERVERWARE_ENROLLMENT_PACKET:-$HOME/Downloads/' + packetFilename + '}"',
        'VERIFIED_ENROLLMENT_PACKET="${SERVERWARE_VERIFIED_ENROLLMENT_PACKET:-${ENROLLMENT_PACKET%.json}.verified.json}"',
        `python3 scripts/generate_agent_enrollment.py --verify-packet "$ENROLLMENT_PACKET" --expected-packet-sha256 ${shellQuote(packetSha256)} --expected-principal ${shellQuote(packet.principalId)} --expected-nonce ${shellQuote(packet.nonce)} --base ${shellQuote(serverware.controlPlaneUrl)} > "$VERIFIED_ENROLLMENT_PACKET"`,
        `python3 scripts/verify_attestation.py --base ${shellQuote(serverware.controlPlaneUrl)} --enrollment-packet "$VERIFIED_ENROLLMENT_PACKET" --ca-out .tmp/serverware-ca.pem --expected-policy-key-hash ${shellQuote(pinning.policySigningKeyId)} --expected-rollback-epoch ${Number(pinning.rollbackEpoch)}`,
        `install -D -m 0644 .tmp/serverware-ca.pem ${shellQuote(ca.installPath)}`,
        `export HTTPS_PROXY=${shellQuote(serverware.proxyUrl)}`,
        `export HTTP_PROXY=${shellQuote(serverware.proxyUrl)}`
      ];
      if (receiptTrust && setupSession?.assignmentDigest && setupSession?.routePolicyDigest) {
        command.push(
          ': "${SERVERWARE_SETUP_ENROLLMENT_VERIFIER_SIGNING_KEY:?set the independent verifier Ed25519 private-key path}"',
          'SETUP_ENROLLMENT_RECEIPT="${SERVERWARE_SETUP_ENROLLMENT_RECEIPT:-${VERIFIED_ENROLLMENT_PACKET%.json}.receipt.json}"',
          `python3 scripts/generate_agent_enrollment.py --sign-setup-receipt --verify-packet "$ENROLLMENT_PACKET" --expected-packet-sha256 ${shellQuote(packetSha256)} --expected-principal ${shellQuote(packet.principalId)} --expected-nonce ${shellQuote(packet.nonce)} --base ${shellQuote(serverware.controlPlaneUrl)} --setup-session-id ${shellQuote(setupSession.id)} --enrollment-session-id ${shellQuote(setupSession.enrollmentSessionId)} --route-id ${shellQuote(setupSession.routeId)} --credential-id ${shellQuote(setupSession.credentialId)} --credential-version ${Number(setupSession.credentialVersion)} --policy-hash ${shellQuote(setupSession.policyHash)} --route-policy-digest ${shellQuote(setupSession.routePolicyDigest)} --expected-assignment-digest ${shellQuote(setupSession.assignmentDigest)} --trust-profile-sha256 ${shellQuote(receiptTrust.digest)} --verifier-provider ${shellQuote(receiptTrust.enrollmentVerifier.provider)} --setup-receipt-signing-key "$SERVERWARE_SETUP_ENROLLMENT_VERIFIER_SIGNING_KEY" --expected-verifier-key-id ${shellQuote(receiptTrust.enrollmentVerifier.keyId)} > "$SETUP_ENROLLMENT_RECEIPT"`
        );
      }
      const commandText = command.join('\n');
      await navigator.clipboard.writeText(commandText);
      return {copied: true, principalId: packet.principalId, setupReceipt: Boolean(receiptTrust)};
    }
    $('admin-token').value = sessionStorage.getItem(tokenKey) || '';
    $('admin-token').addEventListener('change', async () => {
      if (adminToken()) sessionStorage.setItem(tokenKey, adminToken());
      else sessionStorage.removeItem(tokenKey);
      renderAuthStatus();
      try {
        await refresh();
        restoreOAuthDraft();
        renderOAuthDefaults(true);
      } catch (_) {}
    });
    restorePendingMutation();
    (async () => {
      try {
        await fetchAuthStatus();
      } catch (_) {
        state.authStatus = {authenticated: false, oidcBrowserLoginConfigured: false};
        renderAuthStatus();
      }
      await refresh();
      restoreOAuthDraft();
      const template = policyTemplates[$('policy-template').value];
      if (template && !$('policy-route-id').value) $('policy-route-id').value = template.routeId;
      syncPolicyTemplateEditor();
    })().catch(() => {});
    setInterval(() => refresh().catch(() => {}), 4000);
  </script>
</body>
</html>
"""
