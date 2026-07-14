from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from mitmproxy import http

from serverware import db, runtime
from serverware.adapters import get_adapter
from serverware.constraints import evaluate_request_constraints, evaluate_response_constraints
from serverware.policies import PolicyDecision
from serverware.policy_bundle import (
    CredentialPolicy,
    PolicySnapshot,
    PrincipalPolicy,
    PROVIDER_ACCOUNT_OPERATION_FIELD,
    RoutePolicy,
    canonical_json,
    credential_injection_target,
    get_policy_snapshot,
    provider_account_scope_value,
    request_url_parts,
)


SENSITIVE_QUERY_KEYS = {"access_token", "api_key", "apikey", "key", "token", "auth", "authorization"}
SECRET_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
STANDARD_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SERVERWARE_SERVICE_AUTH_HEADERS = {
    "x-serverware-admin-token",
    "x-serverware-audit-anchor-token",
    "x-serverware-ca-install-token",
    "x-serverware-csrf-token",
    "x-serverware-data-plane-token",
}
RESPONSE_PROOF_NONCE_HEADER = "x-serverware-proof-nonce"
_RESPONSE_CREDENTIAL_GUARD_ATTR = "_serverware_response_credential_guard"


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


class _ResponseCredentialGuard:
    def __init__(self) -> None:
        self._patterns: list[bytearray] = []

    def add_text_encodings(self, value: str) -> None:
        raw = value.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest().encode("ascii")
        candidates = [
            raw,
            quote(value, safe="").encode("ascii"),
            quote_plus(value, safe="").encode("ascii"),
            base64.b64encode(raw),
            base64.urlsafe_b64encode(raw).rstrip(b"="),
            digest,
            b"sha256:" + digest,
        ]
        for ensure_ascii in (False, True):
            encoded = json.dumps(value, ensure_ascii=ensure_ascii)
            candidates.append(encoded[1:-1].encode("utf-8"))
        for candidate in candidates:
            if candidate and not any(pattern == candidate for pattern in self._patterns):
                self._patterns.append(bytearray(candidate))

    def detects(self, value: bytes) -> bool:
        return any(value.find(pattern) >= 0 for pattern in self._patterns)

    def detects_response(self, response: Any) -> bool:
        if not response:
            return False
        raw_content = getattr(response, "raw_content", None)
        if isinstance(raw_content, (bytes, bytearray)) and self.detects(bytes(raw_content)):
            return True
        try:
            content = response.content
        except Exception:
            content = None
        if isinstance(content, (bytes, bytearray)) and content != raw_content and self.detects(bytes(content)):
            return True
        headers = getattr(response, "headers", {})
        fields = getattr(headers, "fields", None)
        values = (value for _, value in fields) if fields is not None else headers.values()
        for value in values:
            encoded = value if isinstance(value, bytes) else str(value).encode("utf-8")
            if self.detects(encoded):
                return True
        return False

    def clear(self) -> None:
        for pattern in self._patterns:
            pattern[:] = b"\x00" * len(pattern)
        self._patterns.clear()


def _install_response_credential_guard(flow: http.HTTPFlow, guard: _ResponseCredentialGuard) -> None:
    existing = getattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, None)
    if isinstance(existing, _ResponseCredentialGuard):
        existing.clear()
    setattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, guard)


def _take_response_credential_guard(flow: http.HTTPFlow) -> _ResponseCredentialGuard | None:
    guard = getattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR, None)
    if hasattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR):
        delattr(flow, _RESPONSE_CREDENTIAL_GUARD_ATTR)
    return guard if isinstance(guard, _ResponseCredentialGuard) else None


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


def _canonical_authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".").lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid request authority port") from exc
    default_port = 443 if parts.scheme.lower() == "https" else 80 if parts.scheme.lower() == "http" else None
    return f"{host}:{port}" if port is not None and port != default_port else host


def _normalized_request_headers(flow: http.HTTPFlow) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in flow.request.headers.items():
        name = str(raw_name).lower()
        if name in headers:
            raise ValueError(f"request repeats header {name} after case normalization")
        headers[name] = str(raw_value)
    return headers


def _canonical_forwarded_request_headers(
    flow: http.HTTPFlow,
    credential_policy: CredentialPolicy | None,
) -> dict[str, str]:
    headers = _normalized_request_headers(flow)
    nominated = {
        name.strip().lower()
        for name in headers.get("connection", "").split(",")
        if name.strip()
    }
    for name in nominated:
        if name in headers:
            raise ValueError(f"Connection nominates supplied header {name}")
    target = credential_injection_target(credential_policy.injection) if credential_policy else None
    credential_header = target[1] if target and target[0] == "header" else None
    forwarded = {
        name: value
        for name, value in headers.items()
        if name not in STANDARD_HOP_BY_HOP_HEADERS
        and name not in nominated
        and name != "authorization"
        and name != credential_header
        and name not in {"host", "content-length", "x-serverware-agent"}
        and name not in SERVERWARE_SERVICE_AUTH_HEADERS
        and name != RESPONSE_PROOF_NONCE_HEADER
    }
    forwarded["host"] = _canonical_authority(flow.request.pretty_url)
    body_length = len(_request_body(flow))
    configured_length = headers.get("content-length")
    if configured_length is not None:
        try:
            parsed_length = int(configured_length)
        except ValueError as exc:
            raise ValueError("invalid content-length") from exc
        if parsed_length < 0 or parsed_length != body_length:
            raise ValueError("content-length does not match buffered request body")
        forwarded["content-length"] = str(parsed_length)
    elif body_length:
        forwarded["content-length"] = str(body_length)
    return dict(sorted(forwarded.items()))


def _credential_injection_collision(
    flow: http.HTTPFlow,
    credential_policy: CredentialPolicy | None,
) -> PolicyDecision | None:
    if credential_policy is None:
        return None
    target = credential_injection_target(credential_policy.injection)
    if target is None:
        return PolicyDecision(
            False,
            "credential injection target is invalid",
            500,
            {"error": "credential_injection_target_invalid"},
        )
    try:
        headers = _normalized_request_headers(flow)
    except ValueError as exc:
        return PolicyDecision(
            False,
            str(exc),
            400,
            {"error": "invalid_forwarding_headers", "detail": str(exc)},
        )
    location, name = target
    if location == "header" and name in headers:
        return PolicyDecision(
            False,
            f"agent header collides with credential injection: {name}",
            403,
            {"error": "credential_injection_header_collision", "header": name},
        )
    if location == "query" and any(
        key == name
        for key, _ in parse_qsl(urlsplit(flow.request.pretty_url).query, keep_blank_values=True)
    ):
        return PolicyDecision(
            False,
            f"agent query key collides with credential injection: {name}",
            403,
            {"error": "credential_injection_query_collision", "queryKey": name},
        )
    return None


def _bind_provider_account_scope(
    route: RoutePolicy,
    credential_policy: CredentialPolicy | None,
    operation_fields: dict[str, str],
) -> PolicyDecision | None:
    constraints = [
        str(constraint.get("id") or "unnamed")
        for constraint in route.constraints
        if constraint.get("type") == "rateLimit"
        and PROVIDER_ACCOUNT_OPERATION_FIELD
        in set(((constraint.get("key") or {}).get("operationFields") or []))
    ]
    if not constraints:
        return None
    provider_account = (
        provider_account_scope_value(
            credential_policy.provider,
            credential_policy.provider_subject,
        )
        if credential_policy is not None
        else None
    )
    if provider_account is None:
        return PolicyDecision(
            False,
            "provider account identity is unavailable for account-scoped quota",
            500,
            {
                "error": "provider_account_identity_unavailable",
                "constraint_ids": constraints,
            },
        )
    operation_fields[PROVIDER_ACCOUNT_OPERATION_FIELD] = provider_account
    return None


def _canonical_request(
    flow: http.HTTPFlow,
    *,
    principal: PrincipalPolicy,
    route: RoutePolicy,
    credential_version: str,
    policy_hash: str,
    operation_fields: dict[str, str],
    forwarded_headers: dict[str, str],
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
            "authority": _canonical_authority(flow.request.pretty_url),
            "path": parts.path or "/",
            "query": sorted(parse_qsl(parts.query, keep_blank_values=True)),
            "headers": forwarded_headers,
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


def _secret_for_injection(secret: str, injection: dict[str, Any]) -> str:
    field = injection.get("field")
    if not field:
        return secret
    if not isinstance(field, str) or not SECRET_FIELD_PATH_RE.fullmatch(field):
        raise ValueError("credential injection field must be a dotted object path")
    try:
        value: Any = json.loads(secret)
    except Exception as exc:
        raise ValueError(f"credential secret is not JSON for field {field}") from exc
    for part in str(field).split("."):
        if not part:
            continue
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"credential secret missing field {field}")
        value = value[part]
    if not isinstance(value, str) or not value:
        raise ValueError(f"credential secret field {field} is not a non-empty string")
    return value


def _inject_credential(flow: http.HTTPFlow, credential_policy: CredentialPolicy, credential: dict[str, Any]) -> str:
    injection = credential_policy.injection or {"type": credential.get("kind", "bearer")}
    injection_type = injection.get("type", credential.get("kind", "bearer"))
    if credential.get("kind") == "oauth2" and (
        injection_type != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise ValueError("managed OAuth credential injection is not canonical access-token-only bearer")
    secret = _secret_for_injection(str(credential["secret"]), injection)
    guard = _ResponseCredentialGuard()
    guard.add_text_encodings(secret)
    installed = False
    try:
        if injection_type == "bearer":
            header = injection.get("header", "Authorization")
            value = f"{injection.get('prefix', 'Bearer ')}{secret}"
            flow.request.headers[header] = value
            guard.add_text_encodings(value)
            reason = f"injected bearer into {header}"
        elif injection_type == "header":
            name = injection.get("name", "X-Api-Key")
            value = f"{injection.get('prefix', '')}{secret}"
            flow.request.headers[name] = value
            guard.add_text_encodings(value)
            reason = f"injected header {name}"
        elif injection_type == "query":
            name = injection.get("name", "access_token")
            flow.request.query[name] = secret
            reason = f"injected query parameter {name}"
        elif injection_type == "cookie":
            name = injection.get("name", "serverware_token")
            current = flow.request.headers.get("Cookie", "")
            flow.request.headers["Cookie"] = f"{current}{'; ' if current else ''}{name}={secret}"
            guard.add_text_encodings(f"{name}={secret}")
            reason = f"injected cookie {name}"
        elif injection_type == "basic":
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
            password_text = str(password)
            raw = f"{username}:{password_text}"
            token = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            value = f"Basic {token}"
            flow.request.headers[injection.get("header", "Authorization")] = value
            guard.add_text_encodings(password_text)
            guard.add_text_encodings(raw)
            guard.add_text_encodings(token)
            guard.add_text_encodings(value)
            reason = "injected basic authorization"
        else:
            raise ValueError(f"unknown injection type {injection_type}")
        _install_response_credential_guard(flow, guard)
        installed = True
        return reason
    finally:
        if not installed:
            guard.clear()


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

    collision_decision = _credential_injection_collision(flow, credential_policy)
    if collision_decision is not None:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            collision_decision.status_code,
            collision_decision.reason,
            pre_policy_audit_context,
        )
        return RequestEvaluation(collision_decision, snapshot, principal, route, credential_policy, params)

    try:
        forwarded_headers = _canonical_forwarded_request_headers(flow, credential_policy)
    except ValueError as exc:
        decision = PolicyDecision(
            False,
            "invalid forwarding headers",
            400,
            {"error": "invalid_forwarding_headers", "detail": str(exc)},
        )
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
            pre_policy_audit_context,
        )
        return RequestEvaluation(decision, snapshot, principal, route, credential_policy, params)

    decision = adapter.validate_request(flow, route, params)
    if not decision.allowed:
        runtime.log_request(route.id, flow.request.method, safe_url, "blocked", decision.status_code, decision.reason, pre_policy_audit_context)
        return RequestEvaluation(decision, snapshot, principal, route, credential_policy, params)

    operation_fields = adapter.operation_fields(flow, route, params)
    provider_account_decision = _bind_provider_account_scope(
        route,
        credential_policy,
        operation_fields,
    )
    if provider_account_decision is not None:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            provider_account_decision.status_code,
            provider_account_decision.reason,
            pre_policy_audit_context,
        )
        return RequestEvaluation(
            provider_account_decision,
            snapshot,
            principal,
            route,
            credential_policy,
            params,
        )
    constraint_decision = evaluate_request_constraints(
        flow,
        route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=credential_version_int,
        operation_fields=operation_fields,
        consume_rate_limits=False,
        policy_hash=snapshot.hash,
    )
    if not constraint_decision.allowed:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            constraint_decision.status_code,
            constraint_decision.reason,
            pre_policy_audit_context,
        )
        return RequestEvaluation(constraint_decision, snapshot, principal, route, credential_policy, params)

    canonical_request = _canonical_request(
        flow,
        principal=principal,
        route=route,
        credential_version=credential_version,
        policy_hash=snapshot.hash,
        operation_fields=operation_fields,
        forwarded_headers=forwarded_headers,
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

    rate_limit_decision = evaluate_request_constraints(
        flow,
        route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=credential_version_int,
        operation_fields=operation_fields,
        consume_rate_limits=True,
        policy_hash=snapshot.hash,
        rate_limits_only=True,
    )
    if not rate_limit_decision.allowed:
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            rate_limit_decision.status_code,
            rate_limit_decision.reason,
            audit_context,
        )
        return RequestEvaluation(rate_limit_decision, snapshot, principal, route, credential_policy, params, request_digest, operation_digest)

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
    flow.metadata["serverware_operation"] = dict(operation_fields)
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
    response_credential_guard = _take_response_credential_guard(flow)
    try:
        return _evaluate_response(flow, response_credential_guard)
    finally:
        if response_credential_guard:
            response_credential_guard.clear()


def _evaluate_response(
    flow: http.HTTPFlow,
    response_credential_guard: _ResponseCredentialGuard | None,
) -> PolicyDecision:
    route = flow.metadata.get("serverware_route")
    params = flow.metadata.get("serverware_params") or {}
    route_id = flow.metadata.get("serverware_route_id")
    if not route:
        if flow.metadata.get("serverware_blocked_response") is True:
            return PolicyDecision(True)
        safe_url = redact_url(flow.request.pretty_url)
        runtime.log_request(
            route_id,
            flow.request.method,
            safe_url,
            "blocked",
            502,
            "response policy context missing",
        )
        return PolicyDecision(
            False,
            "response policy context missing",
            502,
            {"error": "response_policy_context_missing"},
        )
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
    if status_code is not None and 200 <= status_code < 300:
        semantic_decision = evaluate_response_constraints(flow, route, constraint_types={"responseJson"})
        if not semantic_decision.allowed:
            runtime.log_request(
                route_id,
                flow.request.method,
                redact_url(flow.request.pretty_url),
                "blocked",
                semantic_decision.status_code,
                semantic_decision.reason,
                audit_context,
            )
            return semantic_decision
    adapter = get_adapter(route.adapter_type)
    decision = adapter.validate_response(flow, route, params)
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
    constraint_decision = (
        evaluate_response_constraints(
            flow,
            route,
            constraint_types={"responseDateWindow"},
        )
        if status_code is not None and 200 <= status_code < 300
        else PolicyDecision(True)
    )
    if not constraint_decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            redact_url(flow.request.pretty_url),
            "blocked",
            constraint_decision.status_code,
            constraint_decision.reason,
            audit_context,
        )
        return constraint_decision
    if response_credential_guard and response_credential_guard.detects_response(flow.response):
        runtime.log_request(
            route_id,
            flow.request.method,
            redact_url(flow.request.pretty_url),
            "blocked",
            502,
            "response credential reflection denied",
            audit_context,
        )
        return PolicyDecision(
            False,
            "response credential reflection denied",
            502,
            {"error": "response_credential_reflection"},
        )
    runtime.log_request(route_id, flow.request.method, redact_url(flow.request.pretty_url), "response", status_code, None, audit_context)
    return decision
