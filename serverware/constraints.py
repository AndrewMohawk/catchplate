from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

from serverware import db
from serverware.policies import PolicyDecision
from serverware.policy_bundle import bounded_pattern_matches, canonical_json, strict_json_loads


SECONDS_PER_DAY = 86_400
SUPPORTED_REQUEST_CONSTRAINTS = {
    "rateLimit",
    "operationPolicy",
    "queryDateWindow",
    "queryNumericBounds",
    "requestTimeWindow",
    "jsonBody",
    "formBody",
}
SUPPORTED_RESPONSE_CONSTRAINTS = {"responseDateWindow", "responseJson", "responseBinding"}
MIN_I64 = -(2**63)
MAX_I64 = 2**63 - 1


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
    skip_shared_rate_limits: bool = False,
    skip_rate_limits: bool = False,
) -> PolicyDecision:
    for constraint in route.constraints:
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_REQUEST_CONSTRAINTS:
            continue
        if not _phase_includes(constraint, "request"):
            continue
        if rate_limits_only and constraint_type != "rateLimit":
            continue
        if skip_rate_limits and constraint_type == "rateLimit":
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
                skip_shared=skip_shared_rate_limits,
            )
        elif constraint_type == "operationPolicy":
            decision = _enforce_operation_policy(constraint, operation_fields)
        elif constraint_type == "queryDateWindow":
            decision = _enforce_query_date_window(constraint, flow.request.pretty_url)
        elif constraint_type == "queryNumericBounds":
            decision = _enforce_query_numeric_bounds(constraint, flow.request.pretty_url)
        elif constraint_type == "requestTimeWindow":
            decision = _enforce_request_time_window(constraint)
        elif constraint_type == "jsonBody":
            decision = _enforce_json_body(constraint, flow)
        elif constraint_type == "formBody":
            decision = _enforce_form_body(constraint, flow)
        else:
            decision = PolicyDecision(True)

        if not decision.allowed:
            return decision

    return PolicyDecision(True)


def evaluate_response_constraints(
    flow: Any,
    route: Any,
    *,
    constraint_types: set[str] | None = None,
) -> PolicyDecision:
    binding_evidence: list[dict[str, str]] = []
    raw_operation_fields = flow.metadata.get("serverware_operation") or {}
    operation_fields = (
        raw_operation_fields if isinstance(raw_operation_fields, dict) else {}
    )
    for constraint in route.constraints:
        if constraint.get("type") != "responseBinding":
            continue
        if constraint_types is not None and "responseBinding" not in constraint_types:
            continue
        if not _phase_includes(constraint, "response"):
            continue
        applies, denial = _constraint_matches_operation(constraint, operation_fields)
        if denial is not None:
            return denial
        if not applies:
            continue
        envelope = _validate_response_binding_envelope(constraint, flow)
        if not envelope.allowed:
            return envelope
    for constraint in route.constraints:
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_RESPONSE_CONSTRAINTS:
            continue
        if constraint_types is not None and constraint_type not in constraint_types:
            continue
        if not _phase_includes(constraint, "response"):
            continue
        operations = constraint.get("operations") or []
        if operations:
            operation_fields = flow.metadata.get("serverware_operation") or {}
            operation = operation_fields.get("operation") if isinstance(operation_fields, dict) else None
            if not isinstance(operation, str) or not operation:
                return _deny(
                    constraint,
                    "response operation context is missing",
                    "response_operation_context_missing",
                    statusCode=502,
                )
            if operation not in operations:
                continue
        if constraint_type == "responseDateWindow":
            decision = _enforce_response_date_window(constraint, flow)
        elif constraint_type == "responseJson":
            decision = _enforce_response_json(constraint, flow)
        elif constraint_type == "responseBinding":
            decision = _enforce_response_binding(constraint, flow, operation_fields)
        else:
            decision = PolicyDecision(True)
        if not decision.allowed:
            return decision
        if constraint_type == "responseBinding":
            binding_evidence.extend(decision.payload.get("bindings") or [])
    return PolicyDecision(
        True,
        payload={"bindings": binding_evidence} if binding_evidence else {},
    )


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


def _canonical_i64(value: Any) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value) is None:
        return None
    parsed = int(value)
    return parsed if MIN_I64 <= parsed <= MAX_I64 else None


def _binding_evidence_digest(
    constraint: dict[str, Any],
    binding: dict[str, Any] | None,
    result: str,
    flow: Any,
) -> str:
    raw = flow.response.raw_content if getattr(flow, "response", None) is not None else b""
    evidence = {
        "policy_hash": str(flow.metadata.get("serverware_policy_hash") or ""),
        "request_digest": str(flow.metadata.get("serverware_request_digest") or ""),
        "operation_digest": str(flow.metadata.get("serverware_operation_digest") or ""),
        "response_body_sha256": "sha256:" + hashlib.sha256(raw or b"").hexdigest(),
        "constraint_id": str(constraint.get("id") or "unnamed"),
        "binding_id": str((binding or {}).get("id") or "constraint"),
        "comparison": str((binding or {}).get("comparison") or "none"),
        "result": result,
    }
    return "sha256:" + hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()


def _binding_denial(
    constraint: dict[str, Any],
    binding: dict[str, Any] | None,
    *,
    error: str,
    reason: str,
    result: str,
    status_code: int,
    flow: Any | None = None,
) -> PolicyDecision:
    payload: dict[str, Any] = {"statusCode": status_code}
    if flow is not None:
        payload["evidence_digest"] = _binding_evidence_digest(
            constraint, binding, result, flow
        )
    if binding is not None:
        payload["binding_id"] = str(binding.get("id") or "unnamed")
    return _deny(constraint, reason, error, **payload)


def _response_header_values(flow: Any, name: str) -> list[str]:
    headers = flow.response.headers
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        return [str(value) for value in get_all(name)]
    value = headers.get(name)
    return [] if value is None else [str(value)]


def _validate_response_binding_envelope(
    constraint: dict[str, Any], flow: Any
) -> PolicyDecision:
    if flow.response is None:
        return _binding_denial(
            constraint,
            None,
            error="response_binding_response_missing",
            reason="response binding requires a response",
            result="response-missing",
            status_code=502,
            flow=flow,
        )
    status_code = int(flow.response.status_code)
    if status_code not in constraint.get("successStatusCodes", []):
        return _binding_denial(
            constraint,
            None,
            error="response_binding_status_denied",
            reason="response status is not admitted by the binding",
            result="status-denied",
            status_code=502,
            flow=flow,
        )
    content_types = _response_header_values(flow, "content-type")
    if len(content_types) != 1:
        return _binding_denial(
            constraint,
            None,
            error="response_binding_content_type_ambiguous",
            reason="response binding requires exactly one content type",
            result="content-type-count",
            status_code=502,
            flow=flow,
        )
    media_type = content_types[0].split(";", 1)[0].strip().lower()
    if media_type not in constraint.get("contentTypes", []):
        return _binding_denial(
            constraint,
            None,
            error="response_binding_content_type_denied",
            reason="response content type is not admitted by the binding",
            result="content-type-denied",
            status_code=502,
            flow=flow,
        )
    content_encodings = _response_header_values(flow, "content-encoding")
    if len(content_encodings) > 1 or (
        content_encodings and content_encodings[0].strip().lower() != "identity"
    ):
        return _binding_denial(
            constraint,
            None,
            error="response_binding_content_encoding_denied",
            reason="response binding requires an identity-encoded body",
            result="content-encoding-denied",
            status_code=502,
            flow=flow,
        )
    return PolicyDecision(True)


def _constraint_matches_operation(
    constraint: dict[str, Any], operation_fields: dict[str, Any]
) -> tuple[bool, PolicyDecision | None]:
    operations = constraint.get("operations") or []
    if not operations:
        return True, None
    operation = operation_fields.get("operation")
    if not isinstance(operation, str) or not operation:
        return False, _binding_denial(
            constraint,
            None,
            error="response_binding_operation_context_missing",
            reason="response binding operation context is missing",
            result="operation-missing",
            status_code=403,
        )
    return operation in operations, None


def evaluate_response_binding_sources(
    route: Any, operation_fields: dict[str, Any]
) -> PolicyDecision:
    for constraint in route.constraints:
        if constraint.get("type") != "responseBinding":
            continue
        applies, denial = _constraint_matches_operation(constraint, operation_fields)
        if denial is not None:
            return denial
        if not applies:
            continue
        for binding in constraint.get("bindings") or []:
            value = operation_fields.get(str(binding.get("operationField") or ""))
            if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
                return _binding_denial(
                    constraint,
                    binding,
                    error="response_binding_source_missing",
                    reason="response binding source is missing or invalid",
                    result="source-missing",
                    status_code=403,
                )
            if binding.get("comparison") == "canonicalInteger" and _canonical_i64(value) is None:
                return _binding_denial(
                    constraint,
                    binding,
                    error="response_binding_source_invalid",
                    reason="response binding integer source is not canonical",
                    result="source-invalid",
                    status_code=403,
                )
    return PolicyDecision(True)


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


def shared_rate_limit_claims(
    route: Any,
    *,
    principal_id: str,
    credential_ref: str | None,
    credential_version: int,
    operation_fields: dict[str, str],
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for constraint in route.constraints:
        if (
            constraint.get("type") != "rateLimit"
            or constraint.get("store", "local") != "shared"
            or not _phase_includes(constraint, "request")
        ):
            continue
        claims.append(
            {
                "counter_key": _rate_key(
                    constraint,
                    route=route,
                    principal_id=principal_id,
                    credential_ref=credential_ref,
                    credential_version=credential_version,
                    operation_fields=operation_fields,
                ),
                "constraint_id": str(constraint.get("id") or "unnamed"),
                "operation": operation_fields.get("operation"),
                "window_seconds": int(constraint.get("windowSeconds") or 0),
                "max_count": int(constraint.get("max") or 0),
            }
        )
    return claims


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
    skip_shared: bool,
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
        if skip_shared:
            return PolicyDecision(True)
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


def _parse_policy_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _clock_minutes(value: Any) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value) is None:
        return None
    hour, minute = value.split(":", 1)
    return int(hour) * 60 + int(minute)


def _enforce_request_time_window(
    constraint: dict[str, Any],
    *,
    now: datetime | None = None,
) -> PolicyDecision:
    if constraint.get("timezone") != "UTC" or not any(
        constraint.get(field) for field in ("notBefore", "notAfter", "weekdays", "dailyWindows")
    ):
        return _deny(
            constraint,
            "request time-window constraint is invalid",
            "constraint_invalid_request_time_window",
        )
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    not_before = (
        _parse_policy_timestamp(constraint.get("notBefore")) if constraint.get("notBefore") is not None else None
    )
    not_after = _parse_policy_timestamp(constraint.get("notAfter")) if constraint.get("notAfter") is not None else None
    if (constraint.get("notBefore") is not None and not_before is None) or (
        constraint.get("notAfter") is not None and not_after is None
    ) or (not_before is not None and not_after is not None and not_before >= not_after):
        return _deny(
            constraint,
            "request time-window constraint is invalid",
            "constraint_invalid_request_time_window",
        )
    if not_before is not None and current < not_before:
        return _deny(
            constraint,
            "request is before the allowed time window",
            "request_time_before_window",
            notBefore=constraint["notBefore"],
        )
    if not_after is not None and current >= not_after:
        return _deny(
            constraint,
            "request is after the allowed time window",
            "request_time_after_window",
            notAfter=constraint["notAfter"],
        )
    weekdays = constraint.get("weekdays")
    weekday = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")[current.weekday()]
    if weekdays is not None and (
        not isinstance(weekdays, list)
        or not weekdays
        or any(
            not isinstance(day, str) or day not in {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
            for day in weekdays
        )
    ):
        return _deny(
            constraint,
            "request time-window constraint is invalid",
            "constraint_invalid_request_time_window",
        )
    if weekdays is not None and weekday not in weekdays:
        return _deny(
            constraint,
            "request weekday is outside the allowed schedule",
            "request_time_weekday_denied",
            weekday=weekday,
        )
    daily_windows = constraint.get("dailyWindows")
    if daily_windows is not None:
        if not isinstance(daily_windows, list) or not daily_windows or any(
            not isinstance(window, dict) for window in daily_windows
        ):
            return _deny(
                constraint,
                "request time-window constraint is invalid",
                "constraint_invalid_request_time_window",
            )
        minute = current.hour * 60 + current.minute
        parsed_windows = [(_clock_minutes(window.get("start")), _clock_minutes(window.get("end"))) for window in daily_windows]
        if any(start is None or end is None or start >= end for start, end in parsed_windows):
            return _deny(
                constraint,
                "request time-window constraint is invalid",
                "constraint_invalid_request_time_window",
            )
        if not any(start <= minute < end for start, end in parsed_windows):
            return _deny(
                constraint,
                "request time is outside the allowed daily windows",
                "request_time_daily_window_denied",
                minuteOfDay=minute,
                timezone="UTC",
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
            if isinstance(parsed, float) and not math.isfinite(parsed):
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
        payload = strict_json_loads(body)
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


def _enforce_form_body(constraint: dict[str, Any], flow: Any) -> PolicyDecision:
    body = _request_body(flow)
    required_fields = [str(item) for item in constraint.get("requiredFields") or []]
    if not body:
        if required_fields:
            return _deny(constraint, "form body is required", "form_body_missing")
        return PolicyDecision(True)
    allowed_content_types = {
        str(item).lower()
        for item in (constraint.get("contentTypes") or ["application/x-www-form-urlencoded"])
    }
    if _content_type(flow) not in allowed_content_types:
        return _deny(
            constraint,
            "request content type is not allowed for form body policy",
            "form_body_content_type_denied",
            contentType=_content_type(flow),
            allowedContentTypes=sorted(allowed_content_types),
        )
    try:
        text = body.decode("utf-8", errors="strict")
        if re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError("invalid percent encoding")
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=256,
        )
    except (UnicodeDecodeError, ValueError):
        return _deny(constraint, "request body is not valid form data", "form_body_invalid")

    values: dict[str, list[str]] = {}
    for raw_key, value in pairs:
        key = _normalize_form_key(raw_key)
        if not key:
            return _deny(constraint, "form body contains an invalid field name", "form_body_field_invalid")
        values.setdefault(key, []).append(value)

    allowed_fields = {str(item) for item in constraint.get("allowedFields") or []}
    if allowed_fields:
        for field in values:
            if field not in allowed_fields:
                return _deny(
                    constraint,
                    "form body contains a field outside the allowlist",
                    "form_body_field_not_allowed",
                    field=field,
                )
    denied_fields = {str(item) for item in constraint.get("deniedFields") or []}
    for field in values:
        if field in denied_fields:
            return _deny(
                constraint,
                "form body contains a denied field",
                "form_body_field_denied",
                field=field,
            )
    for field in required_fields:
        if field not in values:
            return _deny(
                constraint,
                "form body is missing a required field",
                "form_body_required_field_missing",
                field=field,
            )

    payload: dict[str, Any] = {}
    rules = constraint.get("fields") or {}
    for field, found in values.items():
        rule = rules.get(field) or {}
        if len(found) > 1 and rule.get("type") != "array":
            return _deny(
                constraint,
                "form body repeats a scalar field",
                "form_body_duplicate_field_denied",
                field=field,
            )
        try:
            value = _coerce_form_value(found, str(rule.get("type") or "string"))
            _set_form_value(payload, field, value)
        except ValueError:
            return _deny(
                constraint,
                "form body field has the wrong type",
                "form_body_field_type_denied",
                field=field,
                expectedType=rule.get("type") or "string",
            )
    for field, rule in rules.items():
        decision = _enforce_field_rule(constraint, payload, str(field), rule, body_kind="form")
        if not decision.allowed:
            return decision
    return PolicyDecision(True)


def _normalize_form_key(key: str) -> str:
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*(?:\[[A-Za-z0-9_.-]+\])*", key) is None:
        return ""
    parts = [part for part in re.split(r"\[([^\]]+)\]", key) if part and not part.isdigit()]
    return ".".join(parts)


def _coerce_form_value(values: list[str], expected_type: str) -> Any:
    if expected_type == "array":
        return list(values)
    if len(values) != 1:
        raise ValueError("scalar form field is repeated")
    value = values[0]
    if expected_type == "string":
        return value
    if expected_type == "integer" and re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if expected_type == "number":
        parsed = float(value)
        if math.isfinite(parsed):
            return parsed
    if expected_type == "boolean" and value in {"true", "false"}:
        return value == "true"
    raise ValueError("unsupported or invalid form field type")


def _set_form_value(payload: dict[str, Any], field: str, value: Any) -> None:
    parts = field.split(".")
    current = payload
    for part in parts[:-1]:
        existing = current.get(part)
        if existing is None:
            existing = {}
            current[part] = existing
        if not isinstance(existing, dict):
            raise ValueError("form field path conflicts with scalar value")
        current = existing
    if parts[-1] in current:
        raise ValueError("form field path is duplicated")
    current[parts[-1]] = value


def _enforce_response_date_window(constraint: dict[str, Any], flow: Any) -> PolicyDecision:
    if not flow.response:
        return PolicyDecision(True)
    try:
        raw = flow.response.raw_content
        if raw is None:
            raw = flow.response.get_content(strict=False) or b""
        payload = strict_json_loads(raw)
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

    items: list[Any] = []
    item_path_found = False
    if item_paths:
        for item_path in item_paths:
            values = _values_at_path(payload, item_path)
            if values:
                item_path_found = True
            for value in values:
                if isinstance(value, list):
                    items.extend(value)
                else:
                    items.append(value)
    else:
        items = [payload]

    if required and item_paths and not item_path_found:
        return _deny(constraint, "response does not contain required items", "response_items_missing", statusCode=502)

    for item in items:
        for field in date_fields:
            values = _values_at_path(item, field)
            if not values:
                if required and not (isinstance(item, list) and not item):
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


def _enforce_response_json(constraint: dict[str, Any], flow: Any) -> PolicyDecision:
    if not flow.response:
        return PolicyDecision(True)
    try:
        raw = flow.response.raw_content
        if raw is None:
            raw = flow.response.get_content(strict=False) or b""
        payload = strict_json_loads(raw)
    except Exception:
        return _deny(
            constraint,
            "response body is not valid JSON",
            "response_json_invalid",
            statusCode=502,
        )

    fields = constraint.get("fields")
    if not isinstance(fields, dict) or not fields:
        return _deny(
            constraint,
            "response JSON constraint is invalid",
            "constraint_invalid_response_json",
            statusCode=502,
        )

    item_paths = [str(item) for item in constraint.get("items") or []]
    items: list[Any] = []
    item_path_found = False
    if item_paths:
        for item_path in item_paths:
            values = _values_at_path(payload, item_path)
            if values:
                item_path_found = True
            for value in values:
                if isinstance(value, list):
                    items.extend(value)
                else:
                    items.append(value)
        if bool(constraint.get("required", True)) and not item_path_found:
            return _deny(
                constraint,
                "response does not contain required JSON items",
                "response_json_items_missing",
                statusCode=502,
            )
    else:
        items = [payload]

    for item in items:
        for field, rule in fields.items():
            decision = _enforce_field_rule(
                constraint,
                item,
                str(field),
                rule,
                body_kind="response",
            )
            if not decision.allowed:
                return decision
    return PolicyDecision(True)


def _enforce_response_binding(
    constraint: dict[str, Any], flow: Any, operation_fields: dict[str, Any]
) -> PolicyDecision:
    if not flow.response:
        return _binding_denial(
            constraint,
            None,
            error="response_binding_response_missing",
            reason="response binding has no response to validate",
            result="response-missing",
            status_code=502,
            flow=flow,
        )
    try:
        raw = flow.response.raw_content
        if raw is None:
            raw = flow.response.get_content(strict=False) or b""
        payload = strict_json_loads(raw)
    except Exception:
        return _binding_denial(
            constraint,
            None,
            error="response_binding_json_invalid",
            reason="response binding body is not strict JSON",
            result="response-invalid-json",
            status_code=502,
            flow=flow,
        )
    if not isinstance(payload, dict):
        return _binding_denial(
            constraint,
            None,
            error="response_binding_object_required",
            reason="response binding requires a top-level JSON object",
            result="response-object-required",
            status_code=502,
            flow=flow,
        )

    for binding in constraint.get("bindings") or []:
        source = operation_fields.get(str(binding.get("operationField") or ""))
        if not isinstance(source, str):
            return _binding_denial(
                constraint,
                binding,
                error="response_binding_source_missing",
                reason="response binding source is missing",
                result="source-missing",
                status_code=502,
                flow=flow,
            )
        found, actual = _object_value_at_path(
            payload, str(binding.get("responseField") or "")
        )
        if not found:
            return _binding_denial(
                constraint,
                binding,
                error="response_binding_field_ambiguous",
                reason="response binding field is missing or ambiguous",
                result="response-field-count",
                status_code=502,
                flow=flow,
            )
        comparison = binding.get("comparison")
        if comparison == "exactString":
            matches = isinstance(actual, str) and actual == source
        elif comparison == "canonicalInteger":
            expected = _canonical_i64(source)
            matches = (
                expected is not None
                and isinstance(actual, int)
                and not isinstance(actual, bool)
                and MIN_I64 <= actual <= MAX_I64
                and actual == expected
            )
        else:
            matches = False
        if not matches:
            return _binding_denial(
                constraint,
                binding,
                error="response_binding_mismatch",
                reason="response does not match the authorized operation context",
                result="mismatch",
                status_code=502,
                flow=flow,
            )
    return PolicyDecision(
        True,
        payload={
            "bindings": [
                {
                    "constraint_id": str(constraint.get("id") or "unnamed"),
                    "binding_id": str(binding.get("id") or "unnamed"),
                    "evidence_digest": _binding_evidence_digest(
                        constraint, binding, "match", flow
                    ),
                }
                for binding in constraint.get("bindings") or []
            ]
        },
    )


def _object_value_at_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    if isinstance(current, (dict, list)):
        return False, None
    return True, current


def _enforce_field_rule(
    constraint: dict[str, Any],
    payload: Any,
    field: str,
    rule: Any,
    *,
    body_kind: str = "json",
) -> PolicyDecision:
    label = {"json": "JSON body", "form": "form body", "response": "response JSON"}.get(
        body_kind, body_kind
    )
    error_prefix = "response_json" if body_kind == "response" else f"{body_kind}_body"
    status = {"statusCode": 502} if body_kind == "response" else {}
    if not isinstance(rule, dict):
        return _deny(
            constraint,
            f"{label} field rule is invalid",
            f"{error_prefix}_field_rule_invalid",
            field=field,
            **status,
        )
    values = _values_at_path(payload, field)
    if rule.get("required") and not values:
        return _deny(
            constraint,
            f"{label} is missing a required field",
            f"{error_prefix}_required_field_missing",
            field=field,
            **status,
        )
    for value in values:
        expected_type = rule.get("type")
        if expected_type and not _matches_type(value, str(expected_type)):
            return _deny(
                constraint,
                f"{label} field has the wrong type",
                f"{error_prefix}_field_type_denied",
                field=field,
                expectedType=expected_type,
                **status,
            )
        if "enum" in rule and value not in rule["enum"]:
            return _deny(
                constraint,
                f"{label} field value is not in the allowed set",
                f"{error_prefix}_field_enum_denied",
                field=field,
                **status,
            )
        if "equals" in rule and value != rule["equals"]:
            return _deny(
                constraint,
                f"{label} field does not match required value",
                f"{error_prefix}_field_equals_denied",
                field=field,
                **status,
            )
        if isinstance(value, str):
            if "minLength" in rule and len(value) < int(rule["minLength"]):
                return _deny(constraint, f"{label} field is too short", f"{error_prefix}_field_min_length", field=field, **status)
            if "maxLength" in rule and len(value) > int(rule["maxLength"]):
                return _deny(constraint, f"{label} field is too long", f"{error_prefix}_field_max_length", field=field, **status)
            pattern = rule.get("pattern")
            if pattern and bounded_pattern_matches(str(pattern), value) is not True:
                return _deny(constraint, f"{label} field does not match pattern", f"{error_prefix}_field_pattern_denied", field=field, **status)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in rule and value < float(rule["min"]):
                return _deny(constraint, f"{label} field is below policy minimum", f"{error_prefix}_field_min", field=field, **status)
            if "max" in rule and value > float(rule["max"]):
                return _deny(constraint, f"{label} field exceeds policy maximum", f"{error_prefix}_field_max", field=field, **status)
        if isinstance(value, list):
            if "minItems" in rule and len(value) < int(rule["minItems"]):
                return _deny(constraint, f"{label} array has too few items", f"{error_prefix}_field_min_items", field=field, **status)
            if "maxItems" in rule and len(value) > int(rule["maxItems"]):
                return _deny(constraint, f"{label} array has too many items", f"{error_prefix}_field_max_items", field=field, **status)
    return PolicyDecision(True)


def _matches_type(value: Any, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
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
        if not value:
            return [prefix] if prefix else []
        paths: list[tuple[str, ...]] = []
        for key, child in value.items():
            paths.extend(_leaf_paths(child, (*prefix, str(key))))
        return paths
    if isinstance(value, list):
        if not value:
            return [prefix] if prefix else []
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
    format_set = set(formats or ["rfc3339", "date", "epochSeconds", "epochMillis"])
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            numeric = float(value)
        except (OverflowError, ValueError):
            return None
        return _parse_epoch_number(numeric, format_set)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return _parse_epoch_number(float(text), format_set)
    if "rfc3339" in format_set:
        parsed = _parse_rfc3339(text)
        if parsed is not None:
            return parsed
    if "date" in format_set:
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
                raise ValueError("date must use YYYY-MM-DD")
            return datetime.combine(date.fromisoformat(text), datetime.min.time(), tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    return None


def _parse_epoch_number(value: float, formats: set[str]) -> float | None:
    if not math.isfinite(value):
        return None
    is_millis = abs(value) >= 10_000_000_000
    if is_millis and "epochMillis" in formats:
        return value / 1000.0
    if not is_millis and "epochSeconds" in formats:
        return value
    return None


def _parse_rfc3339(text: str) -> float | None:
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        text,
    ):
        return None
    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(normalized)
        return parsed.timestamp()
    except ValueError:
        return None
