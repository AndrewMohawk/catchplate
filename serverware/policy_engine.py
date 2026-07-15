from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from mitmproxy import http

from serverware import db, runtime
from serverware.adapters import get_adapter
from serverware.constraints import (
    evaluate_request_constraints,
    evaluate_response_binding_sources,
    evaluate_response_constraints,
    shared_rate_limit_claims,
)
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
    is_serverware_internal_header,
    normalized_credential_provider,
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
_RELEASE_AUTHORIZATION_ID_MAX_BYTES = 256
_UINT64_MAX = (1 << 64) - 1


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
    attempt_id: str | None = None
    binding_digest: str | None = None
    release_state: str | None = None


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


def redact_url(
    url: str,
    *,
    sensitive_query_keys: tuple[str, ...] = (),
) -> str:
    parts = urlsplit(url)
    sensitive_keys = SENSITIVE_QUERY_KEYS | {
        key.lower() for key in sensitive_query_keys if isinstance(key, str) and key
    }
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in sensitive_keys:
            query.append((key, "redacted"))
        else:
            query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _credential_sensitive_query_keys(
    credential_policy: CredentialPolicy | None,
) -> tuple[str, ...]:
    if credential_policy is None:
        return ()
    target = credential_injection_target(credential_policy.injection)
    if target is None or target[0] != "query":
        return ()
    return (target[1],)


def _audit_url(flow: http.HTTPFlow) -> str:
    query_keys = flow.metadata.get("serverware_sensitive_query_keys")
    sensitive_query_keys = (
        tuple(key for key in query_keys if isinstance(key, str) and key)
        if isinstance(query_keys, (list, tuple))
        else ()
    )
    preserved = flow.metadata.get("serverware_audit_url")
    if isinstance(preserved, str) and preserved:
        return redact_url(
            preserved,
            sensitive_query_keys=sensitive_query_keys,
        )
    return redact_url(
        flow.request.pretty_url,
        sensitive_query_keys=sensitive_query_keys,
    )


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
        and not is_serverware_internal_header(name)
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
    attempt_id: str | None = None,
    binding_digest: str | None = None,
    release_state: str | None = None,
) -> dict[str, Any]:
    return {
        "principal_id": principal.id,
        "policy_hash": snapshot.hash,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "release_state": release_state,
        "route_adapter": route.adapter_type,
    }


def _strip_identity_headers(flow: http.HTTPFlow, principal: PrincipalPolicy) -> None:
    for name in principal.required_headers:
        if name in flow.request.headers:
            del flow.request.headers[name]
    if "Proxy-Authorization" in flow.request.headers:
        del flow.request.headers["Proxy-Authorization"]
    for name in list(flow.request.headers):
        if is_serverware_internal_header(name):
            del flow.request.headers[name]


def _canonical_oauth_scopes(raw_scopes: Any, *, field_name: str) -> frozenset[str]:
    if not isinstance(raw_scopes, list) or not raw_scopes:
        raise ValueError(f"{field_name} must be a non-empty array")
    scopes: list[str] = []
    for scope in raw_scopes:
        if (
            not isinstance(scope, str)
            or not scope
            or scope != scope.strip()
            or any(character.isspace() for character in scope)
        ):
            raise ValueError(f"{field_name} contains an invalid scope")
        scopes.append(scope)
    if len(scopes) > 30 or any(len(scope) > 200 for scope in scopes):
        raise ValueError(f"{field_name} is too large")
    if len(scopes) != len(set(scopes)):
        raise ValueError(f"{field_name} contains duplicate scopes")
    return frozenset(scopes)


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
        raise ValueError("credential scope metadata is invalid")
    if len(scopes) != len(set(scopes)):
        raise ValueError("credential scope metadata contains duplicates")
    return frozenset(scopes)


def _credential_policy_binding_decision(
    credential_policy: CredentialPolicy,
    credential: dict[str, Any],
) -> PolicyDecision | None:
    metadata = credential.get("metadata") or {}
    if not isinstance(metadata, dict):
        return PolicyDecision(
            False,
            "credential metadata is invalid",
            503,
            {"error": "credential_policy_binding_invalid"},
        )

    policy_provider = normalized_credential_provider(credential_policy.provider)
    stored_provider = normalized_credential_provider(
        metadata.get("provider_id") or metadata.get("provider")
    )
    if policy_provider not in {"", "generic"} and stored_provider != policy_provider:
        return PolicyDecision(
            False,
            "stored credential provider does not match the active signed policy",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "provider"},
        )
    if credential_policy.provider_subject is not None and credential.get("kind") != "oauth2":
        return PolicyDecision(
            False,
            "signed provider account binding requires a verified OAuth credential",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
        )

    if credential.get("kind") == "oauth2":
        try:
            verified_provider, stored_subject = db.validate_managed_oauth_identity(metadata)
        except db.ManagedOAuthCredentialError as exc:
            return PolicyDecision(
                False,
                str(exc),
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
            )
        if normalized_credential_provider(verified_provider) != policy_provider:
            return PolicyDecision(
                False,
                "verified OAuth provider does not match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "provider"},
            )
        policy_subject = credential_policy.provider_subject
        if (
            not isinstance(policy_subject, str)
            or not policy_subject
            or stored_subject != policy_subject
        ):
            return PolicyDecision(
                False,
                "stored OAuth account does not match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "providerSubject"},
            )
        try:
            stored_scopes = _canonical_oauth_scopes(
                metadata.get("scopes"),
                field_name="OAuth credential metadata scopes",
            )
            policy_scopes = _canonical_oauth_scopes(
                list(credential_policy.scopes),
                field_name="signed policy OAuth scopes",
            )
        except ValueError as exc:
            return PolicyDecision(
                False,
                str(exc),
                503,
                {"error": "credential_policy_binding_invalid", "binding": "scope"},
            )
        if stored_scopes != policy_scopes:
            return PolicyDecision(
                False,
                "stored OAuth scopes do not exactly match the active signed policy",
                409,
                {"error": "credential_policy_binding_mismatch", "binding": "scope"},
            )
        return None

    policy_scopes = frozenset(str(item) for item in credential_policy.scopes)
    try:
        stored_scopes = _credential_metadata_scopes(metadata)
    except ValueError as exc:
        return PolicyDecision(
            False,
            str(exc),
            503,
            {"error": "credential_policy_binding_invalid", "binding": "scope"},
        )
    if not stored_scopes.issubset(policy_scopes):
        return PolicyDecision(
            False,
            "stored credential scopes exceed the active signed policy",
            409,
            {"error": "credential_policy_binding_mismatch", "binding": "scope"},
        )
    return None


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
            reason = "injected query credential"
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


def _release_lifecycle(flow: http.HTTPFlow) -> dict[str, Any] | None:
    lifecycle = flow.metadata.get("serverware_release_authorization")
    return lifecycle if isinstance(lifecycle, dict) else None


def _valid_release_authorization_identity(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value.encode("utf-8")) <= _RELEASE_AUTHORIZATION_ID_MAX_BYTES
        and all(character.isprintable() for character in value)
    )


def _validated_successful_release_reserve(
    reserved: dict[str, Any],
    *,
    attempt_id: str,
    jit_required: bool,
) -> dict[str, str | int | None] | None:
    binding_digest = reserved.get("binding_digest")
    reservation_expires_at_epoch_ms = reserved.get(
        "reservation_expires_at_epoch_ms"
    )
    grant_id = reserved.get("grant_id")
    approval_request_id = reserved.get("approval_request_id")
    exact_lifecycle = (
        reserved.get("authorized") is True
        and reserved.get("state") == "reserved"
        and reserved.get("reason") == "reserved"
        and reserved.get("attempt_id") == attempt_id
        and isinstance(binding_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", binding_digest) is not None
        and reserved.get("completion_outcome") is None
        and isinstance(reservation_expires_at_epoch_ms, int)
        and not isinstance(reservation_expires_at_epoch_ms, bool)
        and 0 <= reservation_expires_at_epoch_ms <= _UINT64_MAX
        and reserved.get("dispatch_started_at_epoch_ms") is None
        and reserved.get("dispatch_expires_at_epoch_ms") is None
        and reserved.get("retry_after_seconds") == 0
        and not isinstance(reserved.get("retry_after_seconds"), bool)
        and reserved.get("approval_status") is None
        and reserved.get("approval_expires_at") is None
        and reserved.get("approval_created") is None
    )
    if not exact_lifecycle:
        return None
    if jit_required:
        if not (
            _valid_release_authorization_identity(grant_id)
            and _valid_release_authorization_identity(approval_request_id)
        ):
            return None
    elif grant_id is not None or approval_request_id is not None:
        return None
    return {
        "binding_digest": binding_digest,
        "reservation_expires_at_epoch_ms": reservation_expires_at_epoch_ms,
        "grant_id": grant_id,
        "approval_request_id": approval_request_id,
    }


def _store_release_lifecycle(
    flow: http.HTTPFlow,
    *,
    attempt_id: str,
    binding_digest: str,
    state: str,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    reservation_expires_at_epoch_ms: int | None = None,
) -> dict[str, Any]:
    lifecycle = {
        "attempt_id": attempt_id,
        "flow_id": attempt_id,
        "binding_digest": binding_digest,
        "state": state,
        "dispatch_attempted": False,
    }
    if grant_id is not None:
        lifecycle["grant_id"] = grant_id
        flow.metadata["serverware_release_grant_id"] = grant_id
    if approval_request_id is not None:
        lifecycle["approval_request_id"] = approval_request_id
        flow.metadata["serverware_release_approval_request_id"] = approval_request_id
    if reservation_expires_at_epoch_ms is not None:
        lifecycle["reservation_expires_at_epoch_ms"] = reservation_expires_at_epoch_ms
    flow.metadata["serverware_release_authorization"] = lifecycle
    flow.metadata["serverware_release_attempt_id"] = attempt_id
    flow.metadata["serverware_release_binding_digest"] = binding_digest
    flow.metadata["serverware_release_state"] = state
    return lifecycle


def _set_release_state(
    flow: http.HTTPFlow,
    lifecycle: dict[str, Any],
    state: str,
    *,
    outcome: str | None = None,
) -> None:
    lifecycle["state"] = state
    if outcome is not None:
        lifecycle["completion_outcome"] = outcome
    flow.metadata["serverware_release_state"] = state
    if outcome is not None:
        flow.metadata["serverware_release_completion_outcome"] = outcome


def complete_release_authorization(
    flow: http.HTTPFlow,
    outcome: str,
) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    if lifecycle is None:
        return PolicyDecision(True)
    state = str(lifecycle.get("state") or "")
    terminal_states = {"cancelled", "committed", "committed_indeterminate"}
    if state in terminal_states:
        if lifecycle.get("completion_outcome") in {None, outcome}:
            return PolicyDecision(True)
        return PolicyDecision(
            False,
            "release authorization already completed with a different outcome",
            503,
            {"error": "release_authorization_completion_conflict"},
        )
    if state not in {"reserved", "dispatching"}:
        return PolicyDecision(
            False,
            "release authorization lifecycle is invalid",
            503,
            {"error": "release_authorization_lifecycle_invalid"},
        )
    try:
        result = runtime.complete_release_authorization(
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            outcome=outcome,
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
        )
    except runtime.ReleaseAuthorizationClientError:
        return PolicyDecision(
            False,
            "release authorization completion is uncertain",
            503,
            {"error": "release_authorization_completion_uncertain"},
        )
    try:
        runtime.validate_complete_release_authorization_response(
            result,
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            outcome=outcome,
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
        )
    except runtime.ReleaseAuthorizationClientError:
        return PolicyDecision(
            False,
            "release authorization completion state is invalid",
            503,
            {"error": "release_authorization_completion_invalid"},
        )
    _set_release_state(
        flow,
        lifecycle,
        str(result["state"]),
        outcome=str(result["completion_outcome"]),
    )
    return PolicyDecision(True)


def dispatch_release_authorization(flow: http.HTTPFlow) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    if lifecycle is None:
        if runtime.atomic_release_authorization_enabled():
            return PolicyDecision(
                False,
                "release authorization lifecycle is missing",
                503,
                {"error": "release_authorization_lifecycle_missing"},
            )
        return PolicyDecision(True)
    if lifecycle.get("state") != "reserved":
        return PolicyDecision(
            False,
            "release authorization is not reserved",
            503,
            {"error": "release_authorization_not_reserved"},
        )
    reservation_expires_at = lifecycle.get("reservation_expires_at_epoch_ms")
    if (
        not isinstance(reservation_expires_at, int)
        or isinstance(reservation_expires_at, bool)
        or reservation_expires_at <= int(time.time() * 1000)
    ):
        cancellation = complete_release_authorization(flow, "not_forwarded")
        if not cancellation.allowed:
            return cancellation
        return PolicyDecision(
            False,
            "release authorization reservation is expired",
            503,
            {"error": "release_authorization_reservation_expired"},
        )
    lifecycle["dispatch_attempted"] = True
    try:
        result = runtime.dispatch_release_authorization(
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
        )
    except runtime.ReleaseAuthorizationClientError:
        complete_release_authorization(flow, "unknown")
        return PolicyDecision(
            False,
            "release authorization dispatch is uncertain",
            503,
            {"error": "release_authorization_dispatch_uncertain"},
        )
    try:
        runtime.validate_dispatch_release_authorization_response(
            result,
            attempt_id=str(lifecycle["attempt_id"]),
            binding_digest=str(lifecycle["binding_digest"]),
            grant_id=lifecycle.get("grant_id"),
            approval_request_id=lifecycle.get("approval_request_id"),
        )
    except runtime.ReleaseAuthorizationClientError:
        complete_release_authorization(flow, "unknown")
        return PolicyDecision(
            False,
            "release authorization dispatch state is invalid",
            503,
            {"error": "release_authorization_dispatch_invalid"},
        )
    _set_release_state(flow, lifecycle, "dispatching")
    return PolicyDecision(True)


def complete_release_authorization_for_error(flow: http.HTTPFlow) -> PolicyDecision:
    lifecycle = _release_lifecycle(flow)
    if lifecycle is None:
        return PolicyDecision(True)
    if lifecycle.get("state") in {"cancelled", "committed", "committed_indeterminate"}:
        return PolicyDecision(True)
    outcome = (
        "unknown"
        if lifecycle.get("dispatch_attempted") or lifecycle.get("state") == "dispatching"
        else "not_forwarded"
    )
    return complete_release_authorization(flow, outcome)


def evaluate_request(flow: http.HTTPFlow) -> RequestEvaluation:
    runtime.prune_expired_caches()
    snapshot = get_policy_snapshot()
    safe_url = redact_url(flow.request.pretty_url)
    flow.metadata["serverware_audit_url"] = safe_url
    if not snapshot:
        decision = PolicyDecision(False, "policy bundle missing", 503, {"error": "policy_bundle_missing"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 503, decision.reason)
        return RequestEvaluation(decision)

    principal = snapshot.identify_principal(_client_ip(flow), flow.request.headers)
    if not principal:
        decision = PolicyDecision(False, "client principal denied", 403, {"error": "client_principal_denied"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, decision.reason)
        return RequestEvaluation(decision, snapshot=snapshot)

    scheme, host, port, path = request_url_parts(flow.request.pretty_url)
    match = snapshot.match_route(scheme, host, port, flow.request.method, path, principal.id)
    if not match:
        decision = PolicyDecision(False, "unknown route denied", 403, {"error": "unknown_route_denied"})
        runtime.log_request(None, flow.request.method, safe_url, "blocked", 403, decision.reason)
        return RequestEvaluation(decision, snapshot=snapshot, principal=principal)

    route = match.route
    params = match.params
    adapter = get_adapter(route.adapter_type)
    credential_policy = snapshot.credentials.get(route.credential_ref or "")
    sensitive_query_keys = _credential_sensitive_query_keys(credential_policy)
    safe_url = redact_url(
        flow.request.pretty_url,
        sensitive_query_keys=sensitive_query_keys,
    )
    flow.metadata.update(
        {
            "serverware_audit_url": safe_url,
            "serverware_sensitive_query_keys": sensitive_query_keys,
            "serverware_route_id": route.id,
            "serverware_policy_hash": snapshot.hash,
            "serverware_principal_id": principal.id,
            "serverware_credential_id": route.credential_ref,
            "serverware_credential_version": 0,
        }
    )
    pre_policy_audit_context = _audit_context(
        snapshot=snapshot,
        principal=principal,
        route=route,
        credential_id=route.credential_ref,
        credential_version=0,
        request_digest=None,
        operation_digest=None,
    )

    def pre_reserve_denial(decision: PolicyDecision) -> RequestEvaluation:
        denial_audit_context = dict(pre_policy_audit_context)
        if (decision.payload or {}).get("constraint_type") == "responseBinding":
            denial_audit_context["response_validation"] = {
                "ok": False,
                **{
                    key: decision.payload[key]
                    for key in ("error", "constraint_id", "constraint_type", "binding_id")
                    if key in decision.payload
                },
            }
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
            denial_audit_context,
        )
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_policy=credential_policy,
            params=params,
        )

    if route.credential_ref and credential_policy is None:
        return pre_reserve_denial(
            PolicyDecision(False, "credential policy missing", 500, {"error": "credential_missing"})
        )
    collision_decision = _credential_injection_collision(flow, credential_policy)
    if collision_decision is not None:
        return pre_reserve_denial(collision_decision)
    try:
        forwarded_headers = _canonical_forwarded_request_headers(flow, credential_policy)
    except ValueError as exc:
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "invalid forwarding headers",
                400,
                {"error": "invalid_forwarding_headers", "detail": str(exc)},
            )
        )
    decision = adapter.validate_request(flow, route, params)
    if not decision.allowed:
        return pre_reserve_denial(decision)
    try:
        operation_fields = adapter.operation_fields(flow, route, params)
    except (TypeError, ValueError):
        return pre_reserve_denial(
            PolicyDecision(
                False,
                "request operation classification failed",
                403,
                {"error": "request_operation_invalid"},
            )
        )
    provider_account_decision = _bind_provider_account_scope(
        route,
        credential_policy,
        operation_fields,
    )
    if provider_account_decision is not None:
        return pre_reserve_denial(provider_account_decision)
    constraint_decision = evaluate_request_constraints(
        flow,
        route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=0,
        operation_fields=operation_fields,
        consume_rate_limits=False,
        policy_hash=snapshot.hash,
        skip_rate_limits=True,
    )
    if not constraint_decision.allowed:
        return pre_reserve_denial(constraint_decision)
    response_binding_source_decision = evaluate_response_binding_sources(route, operation_fields)
    if not response_binding_source_decision.allowed:
        return pre_reserve_denial(response_binding_source_decision)

    try:
        credential_version_value = runtime.get_credential_version(route.credential_ref)
    except Exception:
        credential_version_value = None
    if credential_version_value is None:
        return pre_reserve_denial(
            PolicyDecision(False, "credential missing", 500, {"error": "credential_missing"})
        )
    credential_version_int = int(credential_version_value)
    credential_version = str(credential_version_int) if credential_version_int else "none"
    flow.metadata["serverware_credential_version"] = credential_version_int

    atomic_mode = runtime.atomic_release_authorization_enabled()
    rate_preview = evaluate_request_constraints(
        flow,
        route,
        principal_id=principal.id,
        credential_ref=route.credential_ref,
        credential_version=credential_version_int,
        operation_fields=operation_fields,
        consume_rate_limits=False,
        policy_hash=snapshot.hash,
        rate_limits_only=True,
        skip_shared_rate_limits=atomic_mode,
    )
    if not rate_preview.allowed:
        return pre_reserve_denial(rate_preview)

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
    jit = route.jit or {}
    jit_required = bool(jit.get("required"))
    attempt_id: str | None = None
    binding_digest: str | None = None
    release_state: str | None = None
    lifecycle: dict[str, Any] | None = None

    def audit_context() -> dict[str, Any]:
        return _audit_context(
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_id=route.credential_ref,
            credential_version=credential_version_int,
            request_digest=request_digest,
            operation_digest=operation_digest,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            release_state=(lifecycle or {}).get("state", release_state),
        )

    def evaluation(decision: PolicyDecision) -> RequestEvaluation:
        return RequestEvaluation(
            decision,
            snapshot=snapshot,
            principal=principal,
            route=route,
            credential_policy=credential_policy,
            params=params,
            request_digest=request_digest,
            operation_digest=operation_digest,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            release_state=(lifecycle or {}).get("state", release_state),
        )

    def block_after_reserve(decision: PolicyDecision) -> RequestEvaluation:
        nonlocal release_state
        if lifecycle is not None and lifecycle.get("state") == "reserved":
            cancellation = complete_release_authorization(flow, "not_forwarded")
            release_state = str(lifecycle.get("state") or release_state)
            if not cancellation.allowed:
                decision = cancellation
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "blocked",
            decision.status_code,
            decision.reason,
            audit_context(),
        )
        return evaluation(decision)

    if atomic_mode:
        attempt_id = str(uuid.uuid4())
        try:
            reserved = runtime.reserve_release_authorization(
                attempt_id=attempt_id,
                flow_id=attempt_id,
                principal_id=principal.id,
                route_id=route.id,
                credential_ref=route.credential_ref,
                credential_version=credential_version_int,
                policy_hash=snapshot.hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                operation_context=dict(operation_fields),
                canonical_request=canonical_request,
                shared_quotas=shared_rate_limit_claims(
                    route,
                    principal_id=principal.id,
                    credential_ref=route.credential_ref,
                    credential_version=credential_version_int,
                    operation_fields=operation_fields,
                ),
                require_jit_grant=jit_required,
            )
        except runtime.ReleaseAuthorizationClientError:
            decision = PolicyDecision(
                False,
                "release authorization reserve is uncertain",
                503,
                {"error": "release_authorization_reserve_uncertain"},
            )
            runtime.log_request(
                route.id,
                flow.request.method,
                safe_url,
                "blocked",
                decision.status_code,
                decision.reason,
                audit_context(),
            )
            return evaluation(decision)
        try:
            runtime.validate_reserve_release_authorization_response(
                reserved,
                attempt_id=attempt_id,
                require_jit_grant=jit_required,
            )
        except runtime.ReleaseAuthorizationClientError:
            binding_digest = str(reserved.get("binding_digest") or "")
            release_state = str(reserved.get("state") or "")
            if (
                release_state == "reserved"
                and reserved.get("attempt_id") == attempt_id
                and re.fullmatch(r"sha256:[0-9a-f]{64}", binding_digest)
                is not None
            ):
                lifecycle = _store_release_lifecycle(
                    flow,
                    attempt_id=attempt_id,
                    binding_digest=binding_digest,
                    state="reserved",
                    grant_id=(
                        reserved.get("grant_id")
                        if _valid_release_authorization_identity(
                            reserved.get("grant_id")
                        )
                        else None
                    ),
                    approval_request_id=(
                        reserved.get("approval_request_id")
                        if _valid_release_authorization_identity(
                            reserved.get("approval_request_id")
                        )
                        else None
                    ),
                    reservation_expires_at_epoch_ms=(
                        reserved.get("reservation_expires_at_epoch_ms")
                        if isinstance(
                            reserved.get("reservation_expires_at_epoch_ms"), int
                        )
                        and not isinstance(
                            reserved.get("reservation_expires_at_epoch_ms"), bool
                        )
                        else None
                    ),
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization reserve state is invalid",
                    503,
                    {"error": "release_authorization_reserve_invalid"},
                )
            )
        binding_digest = str(reserved.get("binding_digest") or "")
        release_state = str(reserved.get("state") or "")
        if release_state == "denied":
            reason = str(reserved.get("reason") or "release_authorization_denied")
            if jit_required and reason in {"jit_grant_unavailable", "jit_grant_expired"}:
                approval_id = reserved.get("approval_request_id")
                approval_status = reserved.get("approval_status")
                approval_expires_at = reserved.get("approval_expires_at")
                approval_created = reserved.get("approval_created")
                retry_after_seconds = reserved.get("retry_after_seconds")
                if (
                    not isinstance(approval_id, str)
                    or not approval_id
                    or approval_status != "pending"
                    or not isinstance(approval_created, bool)
                    or not isinstance(approval_expires_at, str)
                    or not approval_expires_at
                    or not isinstance(retry_after_seconds, int)
                    or isinstance(retry_after_seconds, bool)
                    or retry_after_seconds < 1
                ):
                    return block_after_reserve(
                        PolicyDecision(
                            False,
                            "jit approval response is invalid",
                            503,
                            {"error": "jit_approval_response_invalid"},
                        )
                    )
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "jit approval required",
                        428,
                        {
                            "error": "serverware_approval_required",
                            "approval_id": approval_id,
                            "approval_url": f"/approvals/{approval_id}",
                            "approval_status": approval_status,
                            "approval_created": approval_created,
                            "request_digest": request_digest,
                            "operation_digest": operation_digest,
                            "route_id": route.id,
                            "principal": principal.id,
                            "expires_at": approval_expires_at,
                            "retry_after_seconds": retry_after_seconds,
                        },
                    )
                )
            if reason == "shared_quota_denied":
                return block_after_reserve(
                    PolicyDecision(
                        False,
                        "credential use rate limit exceeded",
                        429,
                        {
                            "error": "credential_rate_limit_exceeded",
                            "retry_after_seconds": int(reserved.get("retry_after_seconds") or 1),
                            "store": "shared",
                        },
                    )
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization denied",
                    503,
                    {"error": "release_authorization_denied", "reason": reason},
                )
            )
        validated_reserve = _validated_successful_release_reserve(
            reserved,
            attempt_id=attempt_id,
            jit_required=jit_required,
        )
        if validated_reserve is None:
            if (
                release_state == "reserved"
                and reserved.get("attempt_id") == attempt_id
                and re.fullmatch(r"sha256:[0-9a-f]{64}", binding_digest)
                is not None
            ):
                lifecycle = _store_release_lifecycle(
                    flow,
                    attempt_id=attempt_id,
                    binding_digest=binding_digest,
                    state="reserved",
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "release authorization reserve state is invalid",
                    503,
                    {"error": "release_authorization_reserve_invalid"},
                )
            )
        binding_digest = str(validated_reserve["binding_digest"])
        lifecycle = _store_release_lifecycle(
            flow,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            state="reserved",
            grant_id=validated_reserve["grant_id"],
            approval_request_id=validated_reserve["approval_request_id"],
            reservation_expires_at_epoch_ms=validated_reserve[
                "reservation_expires_at_epoch_ms"
            ],
        )

    try:
        credential = runtime.get_credential(route.credential_ref) if route.credential_ref else None
    except Exception:
        return block_after_reserve(
            PolicyDecision(False, "credential unavailable", 503, {"error": "credential_unavailable"})
        )
    try:
        loaded_credential_version = int((credential or {}).get("credential_version") or 0)
    except (AttributeError, TypeError, ValueError):
        loaded_credential_version = -1
    if route.credential_ref and loaded_credential_version != credential_version_int:
        return block_after_reserve(
            PolicyDecision(
                False,
                "credential changed during authorization",
                409,
                {"error": "credential_version_changed"},
            )
        )
    try:
        credential_decision = adapter.validate_credential(route, credential)
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "credential validation failed",
                500,
                {"error": "credential_validation_failed"},
            )
        )
    if not credential_decision.allowed:
        return block_after_reserve(credential_decision)
    if credential_policy is not None and credential is not None:
        try:
            binding_decision = _credential_policy_binding_decision(
                credential_policy,
                credential,
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "credential policy binding validation failed",
                    500,
                    {"error": "credential_policy_binding_invalid"},
                )
            )
        if binding_decision is not None:
            return block_after_reserve(binding_decision)

    grant_lookup = {
        "principal_id": principal.id,
        "route_id": route.id,
        "credential_id": route.credential_ref or "",
        "credential_version": credential_version_int,
        "policy_hash": snapshot.hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
    }
    grant_preview: dict[str, Any] = {}
    if jit_required and not atomic_mode:
        try:
            grant_preview = db.find_jit_grant_result(**grant_lookup)
        except Exception:
            return block_after_reserve(
                PolicyDecision(False, "jit grant store unavailable", 503, {"error": "jit_grant_store_unavailable"})
            )
        if not grant_preview.get("available"):
            try:
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
                    pending_ttl_seconds=int(jit.get("pendingTtlSeconds", 300)),
                    grant_ttl_seconds=int(jit.get("ttlSeconds", 30)),
                    grant_max_uses=int(jit.get("maxUses", 1)),
                )
            except Exception:
                return block_after_reserve(
                    PolicyDecision(False, "jit approval store unavailable", 503, {"error": "jit_approval_store_unavailable"})
                )
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "jit approval required",
                    428,
                    {
                        "error": "serverware_approval_required",
                        "approval_id": approval["id"],
                        "approval_url": f"/approvals/{approval['id']}",
                        "request_digest": request_digest,
                        "operation_digest": operation_digest,
                        "route_id": route.id,
                        "principal": principal.id,
                        "expires_at": approval["expires_at"],
                        "retry_after_seconds": 3,
                    },
                )
            )

    try:
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
            skip_shared_rate_limits=atomic_mode,
        )
    except Exception:
        return block_after_reserve(
            PolicyDecision(
                False,
                "request rate-limit validation failed",
                503,
                {"error": "rate_limit_validation_failed"},
            )
        )
    if not rate_limit_decision.allowed:
        return block_after_reserve(rate_limit_decision)

    if jit_required and not atomic_mode:
        try:
            grant_commit = db.consume_jit_grant_result(
                **grant_lookup,
                flow_id=str(uuid.uuid4()),
            )
        except Exception:
            return block_after_reserve(
                PolicyDecision(False, "jit grant store unavailable", 503, {"error": "jit_grant_store_unavailable"})
            )
        if not grant_commit.get("consumed"):
            return block_after_reserve(
                PolicyDecision(
                    False,
                    "approved JIT grant changed before final consumption",
                    409,
                    {
                        "error": "jit_grant_commit_race",
                        "reason": grant_commit.get("reason"),
                        "approval_id": grant_preview.get("approval_id"),
                    },
                )
            )

    try:
        decision = adapter.rewrite_request(flow, route, params)
    except Exception:
        return block_after_reserve(
            PolicyDecision(False, "request rewrite failed", 500, {"error": "request_rewrite_failed"})
        )
    if not decision.allowed:
        return block_after_reserve(decision)

    injection_reason = "no credential configured"
    if credential_policy and credential:
        try:
            injection_reason = _inject_credential(flow, credential_policy, credential)
        except (KeyError, TypeError, ValueError):
            return block_after_reserve(
                PolicyDecision(False, "credential injection failed", 500, {"error": "credential_injection_failed"})
            )

    try:
        _strip_identity_headers(flow, principal)
        flow.metadata.update(
            {
                "serverware_route_id": route.id,
                "serverware_policy_hash": snapshot.hash,
                "serverware_principal_id": principal.id,
                "serverware_credential_id": route.credential_ref,
                "serverware_credential_version": credential_version_int,
                "serverware_request_digest": request_digest,
                "serverware_operation_digest": operation_digest,
                "serverware_operation": dict(operation_fields),
                "serverware_route": route,
                "serverware_params": params,
            }
        )
        runtime.log_request(
            route.id,
            flow.request.method,
            safe_url,
            "allowed",
            None,
            injection_reason,
            audit_context(),
        )
    except Exception:
        return block_after_reserve(
            PolicyDecision(False, "request preparation failed", 503, {"error": "request_preparation_failed"})
        )
    return evaluation(PolicyDecision(True))


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
        safe_url = _audit_url(flow)
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
    raw_upstream_response = flow.response.raw_content if flow.response else b""
    upstream_response_body_sha256 = (
        "sha256:" + hashlib.sha256(raw_upstream_response or b"").hexdigest()
    )
    audit_context = {
        "principal_id": flow.metadata.get("serverware_principal_id"),
        "policy_hash": flow.metadata.get("serverware_policy_hash"),
        "credential_id": flow.metadata.get("serverware_credential_id"),
        "credential_version": flow.metadata.get("serverware_credential_version"),
        "request_digest": flow.metadata.get("serverware_request_digest"),
        "operation_digest": flow.metadata.get("serverware_operation_digest"),
        "attempt_id": flow.metadata.get("serverware_release_attempt_id"),
        "binding_digest": flow.metadata.get("serverware_release_binding_digest"),
        "release_state": flow.metadata.get("serverware_release_state"),
        "completion_outcome": flow.metadata.get(
            "serverware_release_completion_outcome"
        ),
        "route_adapter": getattr(route, "adapter_type", None),
    }
    response_binding_audit: dict[str, Any] | None = None
    if status_code is not None and 200 <= status_code < 300:
        semantic_decision = evaluate_response_constraints(
            flow, route, constraint_types={"responseJson", "responseBinding"}
        )
        if not semantic_decision.allowed:
            payload = semantic_decision.payload or {}
            response_binding_audit = {
                key: payload[key]
                for key in (
                    "error",
                    "constraint_id",
                    "constraint_type",
                    "binding_id",
                    "evidence_digest",
                )
                if key in payload
            }
            denied_audit_context = dict(audit_context)
            denied_audit_context["response_validation"] = {
                "ok": False,
                **response_binding_audit,
            }
            denied_audit_context["response_body_sha256"] = upstream_response_body_sha256
            runtime.log_request(
                route_id,
                flow.request.method,
                _audit_url(flow),
                "blocked",
                semantic_decision.status_code,
                semantic_decision.reason,
                denied_audit_context,
            )
            return semantic_decision
        if semantic_decision.payload.get("bindings"):
            response_binding_audit = {
                "ok": True,
                "bindings": semantic_decision.payload["bindings"],
            }
    adapter = get_adapter(route.adapter_type)
    decision = adapter.validate_response(flow, route, params)
    if not decision.allowed:
        runtime.log_request(
            route_id,
            flow.request.method,
            _audit_url(flow),
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
            _audit_url(flow),
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
            _audit_url(flow),
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
    if response_binding_audit is not None:
        audit_context = dict(audit_context)
        audit_context["response_validation"] = response_binding_audit
        audit_context["response_body_sha256"] = upstream_response_body_sha256
    runtime.log_request(
        route_id,
        flow.request.method,
        _audit_url(flow),
        "response",
        status_code,
        None,
        audit_context,
    )
    return decision
