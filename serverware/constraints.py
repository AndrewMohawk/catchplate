from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

from serverware import db
from serverware.policies import PolicyDecision
from serverware.policy_bundle import canonical_json


SECONDS_PER_DAY = 86_400
SUPPORTED_REQUEST_CONSTRAINTS = {
    "rateLimit",
    "operationPolicy",
    "queryDateWindow",
    "queryNumericBounds",
    "jsonBody",
}
SUPPORTED_RESPONSE_CONSTRAINTS = {"responseDateWindow"}


@dataclass
class _RateBucket:
    window_start: int
    count: int


_RATE_LOCK = threading.Lock()
_RATE_BUCKETS: dict[str, _RateBucket] = {}


def reset_local_constraint_state() -> None:
    with _RATE_LOCK:
        _RATE_BUCKETS.clear()


def evaluate_request_constraints(
    flow: Any,
    route: Any,
    *,
    principal_id: str,
    credential_ref: str | None,
    credential_version: int,
    operation_fields: dict[str, str],
    consume_rate_limits: bool,
    policy_hash: str | None = None,
    rate_limits_only: bool = False,
) -> PolicyDecision:
    for constraint in route.constraints:
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_REQUEST_CONSTRAINTS:
            continue
        if not _phase_includes(constraint, "request"):
            continue
        if rate_limits_only and constraint_type != "rateLimit":
            continue

        if constraint_type == "rateLimit":
            decision = _enforce_rate_limit(
                constraint,
                route=route,
                principal_id=principal_id,
                credential_ref=credential_ref,
                credential_version=credential_version,
                policy_hash=policy_hash,
                operation_fields=operation_fields,
                consume=consume_rate_limits,
            )
        elif constraint_type == "operationPolicy":
            decision = _enforce_operation_policy(constraint, operation_fields)
        elif constraint_type == "queryDateWindow":
            decision = _enforce_query_date_window(constraint, flow.request.pretty_url)
        elif constraint_type == "queryNumericBounds":
            decision = _enforce_query_numeric_bounds(constraint, flow.request.pretty_url)
        elif constraint_type == "jsonBody":
            decision = _enforce_json_body(constraint, flow)
        else:
            decision = PolicyDecision(True)

        if not decision.allowed:
            return decision

    return PolicyDecision(True)


def evaluate_response_constraints(flow: Any, route: Any) -> PolicyDecision:
    for constraint in route.constraints:
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_RESPONSE_CONSTRAINTS:
            continue
        if not _phase_includes(constraint, "response"):
            continue
        if constraint_type == "responseDateWindow":
            decision = _enforce_response_date_window(constraint, flow)
        else:
            decision = PolicyDecision(True)
        if not decision.allowed:
            return decision
    return PolicyDecision(True)


def _phase_includes(constraint: dict[str, Any], phase: str) -> bool:
    configured = constraint.get("phase") or "request"
    if configured == "both":
        return True
    return configured == phase


def _deny(constraint: dict[str, Any], reason: str, error: str, **payload: Any) -> PolicyDecision:
    constraint_id = str(constraint.get("id") or "unnamed")
    status_code = int(payload.pop("statusCode", constraint.get("statusCode") or 403))
    return PolicyDecision(
        False,
        reason,
        status_code,
        {
            "error": error,
            "constraint_id": constraint_id,
            "constraint_type": constraint.get("type"),
            **payload,
        },
    )


def _rate_key(
    constraint: dict[str, Any],
    *,
    route: Any,
    principal_id: str,
    credential_ref: str | None,
    credential_version: int,
    operation_fields: dict[str, str],
) -> str:
    key_config = constraint.get("key") or {}
    scope = key_config.get("scope") or ["principal", "credential", "route", "operation"]
    material: dict[str, Any] = {"constraint": constraint.get("id")}
    for item in scope:
        if item == "principal":
            material[item] = principal_id
        elif item == "credential":
            material[item] = credential_ref or ""
        elif item == "credentialVersion":
            material[item] = credential_version
        elif item == "route":
            material[item] = route.id
        elif item == "operation":
            material[item] = operation_fields.get("operation") or ""
        elif isinstance(item, str) and item.startswith("operation."):
            material[item] = operation_fields.get(item.split(".", 1)[1]) or ""
    for field in key_config.get("operationFields") or []:
        material[f"operation.{field}"] = operation_fields.get(str(field)) or ""
    return "sha256:" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _enforce_rate_limit(
    constraint: dict[str, Any],
    *,
    route: Any,
    principal_id: str,
    credential_ref: str | None,
    credential_version: int,
    policy_hash: str | None,
    operation_fields: dict[str, str],
    consume: bool,
) -> PolicyDecision:
    maximum = int(constraint.get("max") or 0)
    window_seconds = int(constraint.get("windowSeconds") or 0)
    if maximum < 1 or window_seconds < 1:
        return _deny(constraint, "rate limit constraint is invalid", "constraint_invalid_rate_limit")

    now = int(time.time())
    key = _rate_key(
        constraint,
        route=route,
        principal_id=principal_id,
        credential_ref=credential_ref,
        credential_version=credential_version,
        operation_fields=operation_fields,
    )
    store = str(constraint.get("store") or "local")
    if store == "shared":
        try:
            result = db.consume_rate_limit(
                counter_key=key,
                principal_id=principal_id,
                route_id=route.id,
                credential_id=credential_ref or "",
                credential_version=credential_version,
                policy_hash=policy_hash or "",
                constraint_id=str(constraint.get("id") or "unnamed"),
                operation=operation_fields.get("operation"),
                window_seconds=window_seconds,
                max_count=maximum,
                consume=consume,
                actor_type="proxy",
                actor_id=route.id,
            )
        except Exception as exc:
            return _deny(
                constraint,
                "shared rate-limit store is unavailable",
                "shared_rate_limit_store_unavailable",
                statusCode=503,
                detail=str(exc),
                store=store,
            )
        if not result.get("allowed"):
            return _deny(
                constraint,
                "credential use rate limit exceeded",
                "credential_rate_limit_exceeded",
                max=maximum,
                windowSeconds=window_seconds,
                retry_after_seconds=result.get("retry_after_seconds", 1),
                remaining=result.get("remaining", 0),
                count=result.get("count"),
                store=store,
            )
        return PolicyDecision(True)

    if store != "local":
        return _deny(
            constraint,
            "rate limit constraint has an unsupported store",
            "constraint_invalid_rate_limit_store",
            store=store,
        )

    with _RATE_LOCK:
        bucket = _RATE_BUCKETS.get(key)
        if bucket is None or now >= bucket.window_start + window_seconds:
            bucket = _RateBucket(window_start=now, count=0)
            _RATE_BUCKETS[key] = bucket
        if bucket.count >= maximum:
            retry_after = max(1, bucket.window_start + window_seconds - now)
            return _deny(
                constraint,
                "credential use rate limit exceeded",
                "credential_rate_limit_exceeded",
                max=maximum,
                windowSeconds=window_seconds,
                retry_after_seconds=retry_after,
                store=constraint.get("store") or "local",
            )
        if consume:
            bucket.count += 1
    return PolicyDecision(True)


def _enforce_operation_policy(constraint: dict[str, Any], operation_fields: dict[str, str]) -> PolicyDecision:
    operation = operation_fields.get("operation") or ""
    denied = {str(item) for item in constraint.get("deniedOperations") or []}
    allowed = {str(item) for item in constraint.get("allowedOperations") or []}
    if operation in denied:
        return _deny(
            constraint,
            "credential operation denied by policy",
            "credential_operation_denied",
            operation=operation,
        )
    if allowed and operation not in allowed:
        return _deny(
            constraint,
            "credential operation is not allowed by policy",
            "credential_operation_not_allowed",
            operation=operation,
            allowedOperations=sorted(allowed),
        )
    return PolicyDecision(True)


def _query_values(url: str, parameter: str) -> list[str]:
    parsed = urlsplit(url)
    return parse_qs(parsed.query, keep_blank_values=True).get(parameter, [])


def _enforce_query_date_window(constraint: dict[str, Any], url: str) -> PolicyDecision:
    parameters = [str(item) for item in constraint.get("parameters") or []]
    required = bool(constraint.get("required", False))
    max_age_days = int(constraint.get("maxAgeDays") or 0)
    if not parameters or max_age_days < 1:
        return _deny(constraint, "query date-window constraint is invalid", "constraint_invalid_query_date_window")

    now = time.time()
    cutoff = now - max_age_days * SECONDS_PER_DAY
    future_skew = int(constraint.get("allowFutureSkewSeconds", 300))
    formats = [str(item) for item in constraint.get("formats") or []]
    for parameter in parameters:
        values = _query_values(url, parameter)
        if not values:
            if required:
                return _deny(
                    constraint,
                    "required query date parameter is missing",
                    "query_date_parameter_missing",
                    parameter=parameter,
                )
            continue
        for value in values:
            parsed = _parse_datetime(value, formats)
            if parsed is None:
                return _deny(
                    constraint,
                    "query date parameter is invalid",
                    "query_date_parameter_invalid",
                    parameter=parameter,
                    value=value,
                )
            if parsed < cutoff:
                return _deny(
                    constraint,
                    "query asks for data outside the allowed age window",
                    "query_date_window_exceeded",
                    parameter=parameter,
                    value=value,
                    maxAgeDays=max_age_days,
                )
            if parsed > now + future_skew:
                return _deny(
                    constraint,
                    "query date parameter is too far in the future",
                    "query_date_future_denied",
                    parameter=parameter,
                    value=value,
                    allowFutureSkewSeconds=future_skew,
                )
    return PolicyDecision(True)


def _enforce_query_numeric_bounds(constraint: dict[str, Any], url: str) -> PolicyDecision:
    parameters = [str(item) for item in constraint.get("parameters") or []]
    required = bool(constraint.get("required", False))
    minimum = constraint.get("min")
    maximum = constraint.get("max")
    integer = bool(constraint.get("integer", False))
    for parameter in parameters:
        values = _query_values(url, parameter)
        if not values:
            if required:
                return _deny(
                    constraint,
                    "required numeric query parameter is missing",
                    "query_numeric_parameter_missing",
                    parameter=parameter,
                )
            continue
        for value in values:
            try:
                parsed = int(value) if integer else float(value)
            except ValueError:
                return _deny(
                    constraint,
                    "numeric query parameter is invalid",
                    "query_numeric_parameter_invalid",
                    parameter=parameter,
                    value=value,
                )
            if minimum is not None and parsed < float(minimum):
                return _deny(
                    constraint,
                    "numeric query parameter is below policy minimum",
                    "query_numeric_min_exceeded",
                    parameter=parameter,
                    value=value,
                    min=minimum,
                )
            if maximum is not None and parsed > float(maximum):
                return _deny(
                    constraint,
                    "numeric query parameter exceeds policy maximum",
                    "query_numeric_max_exceeded",
                    parameter=parameter,
                    value=value,
                    max=maximum,
                )
    return PolicyDecision(True)


def _request_body(flow: Any) -> bytes:
    raw = getattr(flow.request, "raw_content", None)
    if raw is not None:
        return raw
    try:
        return flow.request.get_content(strict=False) or b""
    except Exception:
        return b""


def _content_type(flow: Any) -> str:
    headers = getattr(flow.request, "headers", {})
    value = headers.get("content-type") or headers.get("Content-Type") or ""
    return str(value).split(";", 1)[0].strip().lower()


def _enforce_json_body(constraint: dict[str, Any], flow: Any) -> PolicyDecision:
    body = _request_body(flow)
    required_fields = [str(item) for item in constraint.get("requiredFields") or []]
    if not body:
        if required_fields:
            return _deny(constraint, "JSON body is required", "json_body_missing")
        return PolicyDecision(True)

    allowed_content_types = {str(item).lower() for item in constraint.get("contentTypes") or []}
    if allowed_content_types and _content_type(flow) not in allowed_content_types:
        return _deny(
            constraint,
            "request content type is not allowed for JSON body policy",
            "json_body_content_type_denied",
            contentType=_content_type(flow),
            allowedContentTypes=sorted(allowed_content_types),
        )

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return _deny(constraint, "request body is not valid JSON", "json_body_invalid")

    allowed_fields = [str(item) for item in constraint.get("allowedFields") or []]
    denied_fields = [str(item) for item in constraint.get("deniedFields") or []]
    if allowed_fields:
        allowed_paths = [tuple(path.split(".")) for path in allowed_fields]
        for leaf_path in _leaf_paths(payload):
            if not _path_allowed(tuple(leaf_path), allowed_paths):
                return _deny(
                    constraint,
                    "JSON body contains a field outside the allowlist",
                    "json_body_field_not_allowed",
                    field=".".join(leaf_path),
                )

    for field in denied_fields:
        if _values_at_path(payload, field):
            return _deny(
                constraint,
                "JSON body contains a denied field",
                "json_body_field_denied",
                field=field,
            )

    for field in required_fields:
        values = _values_at_path(payload, field)
        if not values:
            return _deny(
                constraint,
                "JSON body is missing a required field",
                "json_body_required_field_missing",
                field=field,
            )

    for field, rule in (constraint.get("fields") or {}).items():
        decision = _enforce_field_rule(constraint, payload, str(field), rule)
        if not decision.allowed:
            return decision

    return PolicyDecision(True)


def _enforce_response_date_window(constraint: dict[str, Any], flow: Any) -> PolicyDecision:
    if not flow.response:
        return PolicyDecision(True)
    try:
        raw = flow.response.raw_content
        if raw is None:
            raw = flow.response.get_content(strict=False) or b""
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return _deny(constraint, "response body is not valid JSON", "response_json_invalid", statusCode=502)

    max_age_days = int(constraint.get("maxAgeDays") or 0)
    if max_age_days < 1:
        return _deny(constraint, "response date-window constraint is invalid", "constraint_invalid_response_date_window")
    cutoff = time.time() - max_age_days * SECONDS_PER_DAY
    now = time.time()
    future_skew = int(constraint.get("allowFutureSkewSeconds", 300))
    required = bool(constraint.get("required", True))
    formats = [str(item) for item in constraint.get("formats") or []]
    item_paths = [str(item) for item in constraint.get("items") or []]
    date_fields = [str(item) for item in constraint.get("dateFields") or []]
    if not date_fields:
        return _deny(constraint, "response date fields are missing", "constraint_invalid_response_date_window")

    items = []
    if item_paths:
        for item_path in item_paths:
            items.extend(_values_at_path(payload, item_path))
    else:
        items = [payload]

    if required and not items:
        return _deny(constraint, "response does not contain required items", "response_items_missing", statusCode=502)

    for item in items:
        for field in date_fields:
            values = _values_at_path(item, field)
            if not values:
                if required:
                    return _deny(
                        constraint,
                        "response item is missing a required date field",
                        "response_date_field_missing",
                        field=field,
                        statusCode=502,
                    )
                continue
            for value in values:
                parsed = _parse_datetime(value, formats)
                if parsed is None:
                    return _deny(
                        constraint,
                        "response date field is invalid",
                        "response_date_field_invalid",
                        field=field,
                        value=value,
                        statusCode=502,
                    )
                if parsed < cutoff:
                    return _deny(
                        constraint,
                        "response contains data outside the allowed age window",
                        "response_date_window_exceeded",
                        field=field,
                        value=value,
                        maxAgeDays=max_age_days,
                        statusCode=502,
                    )
                if parsed > now + future_skew:
                    return _deny(
                        constraint,
                        "response date field is too far in the future",
                        "response_date_future_denied",
                        field=field,
                        value=value,
                        allowFutureSkewSeconds=future_skew,
                        statusCode=502,
                    )
    return PolicyDecision(True)


def _enforce_field_rule(constraint: dict[str, Any], payload: Any, field: str, rule: Any) -> PolicyDecision:
    if not isinstance(rule, dict):
        return _deny(constraint, "JSON body field rule is invalid", "json_body_field_rule_invalid", field=field)
    values = _values_at_path(payload, field)
    if rule.get("required") and not values:
        return _deny(
            constraint,
            "JSON body is missing a required field",
            "json_body_required_field_missing",
            field=field,
        )
    for value in values:
        expected_type = rule.get("type")
        if expected_type and not _matches_type(value, str(expected_type)):
            return _deny(
                constraint,
                "JSON body field has the wrong type",
                "json_body_field_type_denied",
                field=field,
                expectedType=expected_type,
            )
        if "enum" in rule and value not in rule["enum"]:
            return _deny(
                constraint,
                "JSON body field value is not in the allowed set",
                "json_body_field_enum_denied",
                field=field,
            )
        if "equals" in rule and value != rule["equals"]:
            return _deny(
                constraint,
                "JSON body field does not match required value",
                "json_body_field_equals_denied",
                field=field,
            )
        if isinstance(value, str):
            if "minLength" in rule and len(value) < int(rule["minLength"]):
                return _deny(constraint, "JSON body field is too short", "json_body_field_min_length", field=field)
            if "maxLength" in rule and len(value) > int(rule["maxLength"]):
                return _deny(constraint, "JSON body field is too long", "json_body_field_max_length", field=field)
            pattern = rule.get("pattern")
            if pattern and not re.search(str(pattern), value):
                return _deny(constraint, "JSON body field does not match pattern", "json_body_field_pattern_denied", field=field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in rule and value < float(rule["min"]):
                return _deny(constraint, "JSON body field is below policy minimum", "json_body_field_min", field=field)
            if "max" in rule and value > float(rule["max"]):
                return _deny(constraint, "JSON body field exceeds policy maximum", "json_body_field_max", field=field)
        if isinstance(value, list):
            if "minItems" in rule and len(value) < int(rule["minItems"]):
                return _deny(constraint, "JSON body array has too few items", "json_body_field_min_items", field=field)
            if "maxItems" in rule and len(value) > int(rule["maxItems"]):
                return _deny(constraint, "JSON body array has too many items", "json_body_field_max_items", field=field)
    return PolicyDecision(True)


def _matches_type(value: Any, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "null":
        return value is None
    return False


def _leaf_paths(value: Any, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    if isinstance(value, dict):
        paths: list[tuple[str, ...]] = []
        for key, child in value.items():
            paths.extend(_leaf_paths(child, (*prefix, str(key))))
        return paths
    if isinstance(value, list):
        paths = []
        for child in value:
            paths.extend(_leaf_paths(child, prefix))
        return paths
    return [prefix]


def _path_allowed(path: tuple[str, ...], allowed_paths: list[tuple[str, ...]]) -> bool:
    for allowed in allowed_paths:
        if path == allowed or path[: len(allowed)] == allowed:
            return True
    return False


def _values_at_path(value: Any, path: str) -> list[Any]:
    parts = [part for part in path.split(".") if part]
    return _values_at_parts(value, parts)


def _values_at_parts(value: Any, parts: list[str]) -> list[Any]:
    if not parts:
        return [value]
    if isinstance(value, list):
        found: list[Any] = []
        for item in value:
            found.extend(_values_at_parts(item, parts))
        return found
    if not isinstance(value, dict):
        return []
    key = parts[0]
    if key == "*":
        found = []
        for item in value.values():
            found.extend(_values_at_parts(item, parts[1:]))
        return found
    if key not in value:
        return []
    return _values_at_parts(value[key], parts[1:])


def _parse_datetime(value: Any, formats: list[str]) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _parse_epoch_number(float(value))
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return _parse_epoch_number(float(text))
    format_set = set(formats or ["rfc3339", "date", "epochSeconds", "epochMillis"])
    if "rfc3339" in format_set:
        parsed = _parse_rfc3339(text)
        if parsed is not None:
            return parsed
    if "date" in format_set:
        try:
            return datetime.combine(date.fromisoformat(text[:10]), datetime.min.time(), tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    return None


def _parse_epoch_number(value: float) -> float:
    if value > 10_000_000_000:
        return value / 1000.0
    return value


def _parse_rfc3339(text: str) -> float | None:
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None
