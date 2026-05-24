from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mitmproxy import http

from serverware import db, runtime
from serverware.adapters import get_adapter
from serverware.policies import PolicyDecision
from serverware.policy_bundle import (
    CredentialPolicy,
    PolicySnapshot,
    PrincipalPolicy,
    RoutePolicy,
    canonical_json,
    get_policy_snapshot,
    request_url_parts,
)


SENSITIVE_QUERY_KEYS = {"access_token", "api_key", "apikey", "key", "token", "auth", "authorization"}
VOLATILE_DIGEST_HEADERS = {"date", "user-agent", "content-length", "connection", "authorization", "proxy-authorization"}


@dataclass
class RequestEvaluation:
    decision: PolicyDecision
    snapshot: PolicySnapshot | None = None
    principal: PrincipalPolicy | None = None
    route: RoutePolicy | None = None
    credential_policy: CredentialPolicy | None = None
    params: dict[str, str] | None = None
    request_digest: str | None = None
    operation_digest: str | None = None


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query.append((key, "redacted"))
        else:
            query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _client_ip(flow: http.HTTPFlow) -> str | None:
    peername = getattr(flow.client_conn, "peername", None) or getattr(flow.client_conn, "address", None)
    if isinstance(peername, tuple) and peername:
        return str(peername[0])
    return None


def _request_body(flow: http.HTTPFlow) -> bytes:
    raw = flow.request.raw_content
    if raw is not None:
        return raw
    try:
        return flow.request.get_content(strict=False) or b""
    except Exception:
        return b""


def _body_sha256(flow: http.HTTPFlow) -> str:
    return "sha256:" + hashlib.sha256(_request_body(flow)).hexdigest()


def _selected_headers(flow: http.HTTPFlow) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in flow.request.headers.items():
        lower = name.lower()
        if lower in VOLATILE_DIGEST_HEADERS or lower.startswith("proxy-"):
            continue
        if lower in {"content-type", "npm-command", "x-serverware-agent"}:
            headers[lower] = value
    return dict(sorted(headers.items()))


def _canonical_request(
    flow: http.HTTPFlow,
    *,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_version: str,
    policy_hash: str,
    operation_fields: dict[str, str],
) -> dict[str, Any]:
    parts = urlsplit(flow.request.pretty_url)
    return {
        "v": 1,
        "principal": principal.id,
        "client_ip": _client_ip(flow),
        "route_id": route.id,
        "credential_ref": route.credential_ref,
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request": {
            "method": flow.request.method.upper(),
            "scheme": parts.scheme,
            "authority": parts.netloc.lower(),
            "path": parts.path or "/",
            "query": sorted(parse_qsl(parts.query, keep_blank_values=True)),
            "headers": _selected_headers(flow),
            "body_sha256": _body_sha256(flow),
        },
        "operation": operation_fields,
    }


def _digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _operation_digest(canonical_request: dict[str, Any]) -> str:
    operation_view = {
        "principal": canonical_request["principal"],
        "route_id": canonical_request["route_id"],
        "credential_ref": canonical_request["credential_ref"],
        "credential_version": canonical_request["credential_version"],
        "policy_hash": canonical_request["policy_hash"],
        "request": canonical_request["request"],
        "operation": canonical_request["operation"],
    }
    return _digest(operation_view)


def _audit_context(
    *,
    snapshot: PolicySnapshot,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_id: str | None,
    credential_version: int,
    request_digest: str | None,
    operation_digest: str | None,
) -> dict[str, Any]:
    return {
        "principal_id": principal.id,
        "policy_hash": snapshot.hash,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "route_adapter": route.adapter_type,
    }


def _strip_identity_headers(flow: http.HTTPFlow, principal: PrincipalPolicy) -> None:
    for name in principal.required_headers:
        if name in flow.request.headers:
            del flow.request.headers[name]
    if "Proxy-Authorization" in flow.request.headers:
        del flow.request.headers["Proxy-Authorization"]


def _inject_credential(flow: http.HTTPFlow, credential_policy: CredentialPolicy, credential: dict[str, Any]) -> str:
    secret = credential["secret"]
    injection = credential_policy.injection or {"type": credential.get("kind", "bearer")}
    injection_type = injection.get("type", credential.get("kind", "bearer"))

    if injection_type == "bearer":
        header = injection.get("header", "Authorization")
        prefix = injection.get("prefix", "Bearer ")
        flow.request.headers[header] = f"{prefix}{secret}"
        return f"injected bearer into {header}"
    if injection_type == "header":
        name = injection.get("name", "X-Api-Key")
        flow.request.headers[name] = f"{injection.get('prefix', '')}{secret}"
        return f"injected header {name}"
    if injection_type == "query":
        name = injection.get("name", "access_token")
        flow.request.query[name] = secret
        return f"injected query parameter {name}"
    if injection_type == "cookie":
        name = injection.get("name", "serverware_token")
        current = flow.request.headers.get("Cookie", "")
        flow.request.headers["Cookie"] = f"{current}{'; ' if current else ''}{name}={secret}"
        return f"injected cookie {name}"
    if injection_type == "basic":
        username = injection.get("username") or credential.get("metadata", {}).get("username")
        password = secret
        try:
            decoded = json.loads(secret)
            username = username or decoded.get("username")
            password = decoded.get("password", password)
        except Exception:
            pass
        if not username:
            raise ValueError("basic credential missing username")
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        flow.request.headers[injection.get("header", "Authorization")] = f"Basic {token}"
        return "injected basic authorization"
    raise ValueError(f"unknown injection type {injection_type}")


def evaluate_request(flow: http.HTTPFlow) -> RequestEvaluation:
    runtime.prune_expired_caches()
    snapshot = get_policy_snapshot()
    safe_url = redact_url(flow.request.pretty_url)
    if not snapshot:
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 503, "policy bundle missing")
        return RequestEvaluation(PolicyDecision(False, "policy bundle missing", 503, {"error": "policy_bundle_missing"}))

    principal = snapshot.identify_principal(_client_ip(flow), flow.request.headers)
    if not principal:
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, "client principal denied")
        return RequestEvaluation(PolicyDecision(False, "client principal denied", 403, {"error": "client_principal_denied"}), snapshot=snapshot)

    scheme, host, port, path = request_url_parts(flow.request.pretty_url)
    match = snapshot.match_route(scheme, host, port, flow.request.method, path, principal.id)
    if not match:
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, "unknown route denied")
        return RequestEvaluation(
            PolicyDecision(False, "unknown route denied", 403, {"error": "unknown_route_denied"}),
            snapshot=snapshot,
            principal=principal,
        )

    route = match.route
    params = match.params
    adapter = get_adapter(route.adapter_type)
    credential_policy = snapshot.credentials.get(route.credential_ref or "")
    credential = runtime.get_credential(route.credential_ref) if route.credential_ref else None
    if route.credential_ref and (not credential_policy or not credential):
        runtime.log_request(route.id, flow.request.method, safe_url, "blocked", 500, "credential missing")
        return RequestEvaluation(
            PolicyDecision(False, "credential missing", 500, {"error": "credential_missing"}),
            snapshot=snapshot,
            principal=principal,
            route=route,
            params=params,
        )

    credential_version_int = int((credential or {}).get("credential_version") or 0)
    credential_version = str(credential_version_int or (credential or {}).get("updated_at") or "none")
    flow.metadata["serverware_route_id"] = route.id
    flow.metadata["serverware_policy_hash"] = snapshot.hash
    flow.metadata["serverware_principal_id"] = principal.id
    flow.metadata["serverware_credential_id"] = route.credential_ref
    flow.metadata["serverware_credential_version"] = credential_version_int
    pre_policy_audit_context = _audit_context(
        snapshot=snapshot,
        principal=principal,
        route=route,
        credential_id=route.credential_ref,
        credential_version=credential_version_int,
        request_digest=None,
        operation_digest=None,
    )

    credential_decision = adapter.validate_credential(route, credential)
    if not credential_decision.allowed:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            credential_decision.status_code,
            credential_decision.reason,
            pre_policy_audit_context,
        )
        return RequestEvaluation(credential_decision, snapshot, principal, route, credential_policy, params)

    decision = adapter.validate_request(flow, route, params)
    if not decision.allowed:
        runtime.log_request(route.id, flow.request.method, safe_url, "blocked", decision.status_code, decision.reason, pre_policy_audit_context)
        return RequestEvaluation(decision, snapshot, principal, route, credential_policy, params)

    operation_fields = adapter.operation_fields(flow, route, params)
    canonical_request = _canonical_request(
        flow,
        principal=principal,
        route=route,
        credential_version=credential_version,
        policy_hash=snapshot.hash,
        operation_fields=operation_fields,
    )
    request_digest = _digest(canonical_request)
    operation_digest = _operation_digest(canonical_request)
    audit_context = _audit_context(
        snapshot=snapshot,
        principal=principal,
        route=route,
        credential_id=route.credential_ref,
        credential_version=credential_version_int,
        request_digest=request_digest,
        operation_digest=operation_digest,
    )

    jit = route.jit or {}
    if jit.get("required"):
        try:
            consumed = db.consume_jit_grant(
                principal_id=principal.id,
                route_id=route.id,
                credential_id=route.credential_ref or "",
                credential_version=credential_version_int,
                policy_hash=snapshot.hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                flow_id=str(uuid.uuid4()),
            )
        except Exception as exc:
            runtime.log_request(
                route.id,
                flow.request.method,
                safe_url,
                "blocked",
                503,
                "jit grant store unavailable",
                {**audit_context, "error": str(exc)},
            )
            return RequestEvaluation(
                PolicyDecision(
                    False,
                    "jit grant store unavailable",
                    503,
                    {"error": "jit_grant_store_unavailable"},
                ),
                snapshot,
                principal,
                route,
                credential_policy,
                params,
                request_digest,
                operation_digest,
            )
        if not consumed:
            pending_ttl = int(jit.get("pendingTtlSeconds", 300))
            grant_ttl = int(jit.get("ttlSeconds", 30))
            max_uses = int(jit.get("maxUses", 1))
            approval = db.ensure_jit_approval_request(
                route_id=route.id,
                method=flow.request.method,
                url=safe_url,
                principal_id=principal.id,
                credential_id=route.credential_ref or "",
                credential_version=credential_version_int,
                policy_hash=snapshot.hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                canonical_request=canonical_request,
                redacted_display={
                    "method": flow.request.method,
                    "url": safe_url,
                    "route_id": route.id,
                    "principal": principal.id,
                    "operation": operation_fields,
                    "body_sha256": canonical_request["request"]["body_sha256"],
                },
                pending_ttl_seconds=pending_ttl,
                grant_ttl_seconds=grant_ttl,
                grant_max_uses=max_uses,
            )
            runtime.log_request(
                route.id,
                flow.request.method,
                safe_url,
                "blocked",
                428,
                "jit approval required",
                {**audit_context, "approval_id": approval["id"]},
            )
            return RequestEvaluation(
                PolicyDecision(
                    False,
                    "jit approval required",
                    428,
                    {
                        "error": "serverware_approval_required",
                        "approval_id": approval["id"],
                        "request_digest": request_digest,
                        "operation_digest": operation_digest,
                        "route_id": route.id,
                        "principal": principal.id,
                        "expires_at": approval["expires_at"],
                        "retry_after_seconds": 3,
                    },
                ),
                snapshot,
                principal,
                route,
                credential_policy,
                params,
                request_digest,
                operation_digest,
            )

        # A grant is only authorization to retry. Re-run policy after consuming it.
        decision = adapter.validate_request(flow, route, params)
        if not decision.allowed:
            runtime.log_request(route.id, flow.request.method, safe_url, "blocked", decision.status_code, decision.reason, audit_context)
            return RequestEvaluation(decision, snapshot, principal, route, credential_policy, params, request_digest, operation_digest)

    decision = adapter.rewrite_request(flow, route, params)
    if not decision.allowed:
        runtime.log_request(route.id, flow.request.method, safe_url, "blocked", decision.status_code, decision.reason, audit_context)
        return RequestEvaluation(decision, snapshot, principal, route, credential_policy, params, request_digest, operation_digest)

    injection_reason = "no credential configured"
    if credential_policy and credential:
        try:
            injection_reason = _inject_credential(flow, credential_policy, credential)
        except ValueError as exc:
            runtime.log_request(route.id, flow.request.method, safe_url, "blocked", 500, str(exc), audit_context)
            return RequestEvaluation(
                PolicyDecision(False, str(exc), 500, {"error": "credential_injection_failed"}),
                snapshot,
                principal,
                route,
                credential_policy,
                params,
                request_digest,
                operation_digest,
            )

    _strip_identity_headers(flow, principal)
    flow.metadata["serverware_route_id"] = route.id
    flow.metadata["serverware_policy_hash"] = snapshot.hash
    flow.metadata["serverware_principal_id"] = principal.id
    flow.metadata["serverware_credential_id"] = route.credential_ref
    flow.metadata["serverware_credential_version"] = credential_version_int
    flow.metadata["serverware_request_digest"] = request_digest
    flow.metadata["serverware_operation_digest"] = operation_digest
    flow.metadata["serverware_route"] = route
    flow.metadata["serverware_params"] = params
    runtime.log_request(route.id, flow.request.method, safe_url, "allowed", None, injection_reason, audit_context)
    return RequestEvaluation(
        PolicyDecision(True),
        snapshot,
        principal,
        route,
        credential_policy,
        params,
        request_digest,
        operation_digest,
    )


def evaluate_response(flow: http.HTTPFlow) -> PolicyDecision:
    route = flow.metadata.get("serverware_route")
    params = flow.metadata.get("serverware_params") or {}
    route_id = flow.metadata.get("serverware_route_id")
    if not route:
        return PolicyDecision(True)
    adapter = get_adapter(route.adapter_type)
    decision = adapter.validate_response(flow, route, params)
    status_code = flow.response.status_code if flow.response else None
    audit_context = {
        "principal_id": flow.metadata.get("serverware_principal_id"),
        "policy_hash": flow.metadata.get("serverware_policy_hash"),
        "credential_id": flow.metadata.get("serverware_credential_id"),
        "credential_version": flow.metadata.get("serverware_credential_version"),
        "request_digest": flow.metadata.get("serverware_request_digest"),
        "operation_digest": flow.metadata.get("serverware_operation_digest"),
        "route_adapter": getattr(route, "adapter_type", None),
    }
    if not decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            redact_url(flow.request.pretty_url),
            "blocked",
            decision.status_code,
            decision.reason,
            audit_context,
        )
        return decision
    runtime.log_request(route_id, flow.request.method, redact_url(flow.request.pretty_url), "response", status_code, None, audit_context)
    return decision
