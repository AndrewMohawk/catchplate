from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from serverware import db
from serverware.config import PUBLIC_URL


SENSITIVE_QUERY_KEYS = {"access_token", "api_key", "apikey", "key", "token", "auth", "authorization"}
GMAIL_LIST_RE = re.compile(r"^/gmail/v1/users/[^/]+/messages/?$")
GMAIL_GET_RE = re.compile(r"^/gmail/v1/users/[^/]+/messages/([^/?#]+)$")
OLDER_THAN_RE = re.compile(r"\bolder_than:(\d+)([dmy])\b", re.IGNORECASE)


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    status_code: int = 403
    payload: dict[str, Any] = field(default_factory=dict)


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            query.append((key, "redacted"))
        else:
            query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def policy_of(route: dict[str, Any], policy_type: str) -> dict[str, Any] | None:
    for policy in route.get("policies", []):
        if policy.get("type") == policy_type:
            return policy
    return None


def _older_than_days(value: str) -> int | None:
    match = OLDER_THAN_RE.search(value)
    if not match:
        return None
    count = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "d":
        return count
    if unit == "m":
        return count * 30
    return count * 365


def _append_gmail_recent_query(query: str, days: int) -> str:
    guard = f"newer_than:{days}d"
    if guard.lower() in query.lower():
        return query
    if not query.strip():
        return guard
    return f"({query}) {guard}"


def _message_id_from_path(path: str) -> str | None:
    match = GMAIL_GET_RE.match(path)
    return match.group(1) if match else None


def apply_request_policies(flow: Any, route: dict[str, Any]) -> PolicyDecision:
    approval = policy_of(route, "approval")
    safe_url = redact_url(flow.request.pretty_url)
    approval_scope = approval.get("scope", "route") if approval else "route"
    approval_url = safe_url if approval_scope == "url" else None
    if approval and not db.has_active_approval(route["id"], url=approval_url):
        pending_ttl = int(approval.get("pending_ttl_seconds", 300))
        approval_request = db.create_approval_request(
            route["id"],
            flow.request.method,
            safe_url,
            ttl_seconds=pending_ttl,
        )
        return PolicyDecision(
            allowed=False,
            status_code=428,
            reason="approval required",
            payload={
                "error": "approval_required",
                "approval_id": approval_request["id"],
                "approve_url": f"{PUBLIC_URL}/approvals",
                "route_id": route["id"],
                "route": route["name"],
                "ttl_seconds": int(approval.get("ttl_seconds", 30)),
            },
        )

    gmail_recent = policy_of(route, "gmail_recent")
    if gmail_recent:
        decision = apply_gmail_recent_policy(flow, route, gmail_recent)
        if not decision.allowed:
            return decision

    return PolicyDecision(allowed=True)


def apply_gmail_recent_policy(flow: Any, route: dict[str, Any], policy: dict[str, Any]) -> PolicyDecision:
    days = int(policy.get("days", 30))
    path = urlsplit(flow.request.pretty_url).path

    if GMAIL_LIST_RE.match(path):
        original_q = flow.request.query.get("q", "")
        older_than = _older_than_days(original_q)
        if older_than and older_than > days:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"gmail query asks for mail older than {days} days",
                payload={"error": "gmail_recent_policy", "max_days": days},
            )
        flow.request.query["q"] = _append_gmail_recent_query(original_q, days)
        max_results = policy.get("max_results")
        if max_results and int(flow.request.query.get("maxResults", max_results)) > int(max_results):
            flow.request.query["maxResults"] = str(max_results)
        return PolicyDecision(allowed=True)

    message_id = _message_id_from_path(path)
    if message_id and not db.gmail_message_allowed(route["id"], message_id):
        return PolicyDecision(
            allowed=False,
            status_code=403,
            reason="gmail message id was not observed in an allowed recent list response",
            payload={"error": "gmail_message_not_recently_listed", "message_id": message_id},
        )

    return PolicyDecision(allowed=True)


def remember_gmail_response(flow: Any, route: dict[str, Any]) -> None:
    policy = policy_of(route, "gmail_recent")
    if not policy or not flow.response:
        return
    path = urlsplit(flow.request.pretty_url).path
    if not GMAIL_LIST_RE.match(path):
        return
    try:
        payload = json.loads(flow.response.get_text(strict=False))
    except Exception:
        return
    messages = payload.get("messages") or []
    message_ids = [item["id"] for item in messages if isinstance(item, dict) and item.get("id")]
    db.cache_gmail_message_ids(
        route["id"],
        message_ids,
        redact_url(flow.request.pretty_url),
        ttl_seconds=int(policy.get("cache_ttl_seconds", 1800)),
    )


def inject_credential(flow: Any, route: dict[str, Any]) -> str:
    credential_id = route.get("credential_id")
    if not credential_id:
        return "no credential configured"
    credential = db.get_credential(credential_id, include_secret=True)
    if not credential:
        return "credential missing"

    secret = credential["secret"]
    injection = route.get("injection") or {}
    injection_type = injection.get("type") or credential.get("kind") or "bearer"

    if injection_type == "bearer":
        header = injection.get("header", "Authorization")
        prefix = injection.get("prefix", "Bearer ")
        flow.request.headers[header] = f"{prefix}{secret}"
        return f"injected bearer into {header}"

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
            return "basic credential missing username"
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        flow.request.headers[injection.get("header", "Authorization")] = f"Basic {token}"
        return "injected basic authorization"

    if injection_type == "header":
        name = injection.get("name", "X-Api-Key")
        prefix = injection.get("prefix", "")
        flow.request.headers[name] = f"{prefix}{secret}"
        return f"injected header {name}"

    if injection_type == "query":
        name = injection.get("name", "access_token")
        flow.request.query[name] = secret
        return f"injected query parameter {name}"

    if injection_type == "cookie":
        name = injection.get("name", "serverware_token")
        current = flow.request.headers.get("Cookie", "")
        sep = "; " if current else ""
        flow.request.headers["Cookie"] = f"{current}{sep}{name}={secret}"
        return f"injected cookie {name}"

    return f"unknown injection type {injection_type}"
