from __future__ import annotations

import csv
import base64
import hashlib
import io
import json
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlunsplit

from serverware import db, http_client, runtime
from serverware.policies import PolicyDecision
from serverware.policy_bundle import (
    BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE,
    BUFFERED_JSON_PASSTHROUGH_REQUEST_MODE,
    BUFFERED_PASSTHROUGH_RESPONSE_MODE,
    GMAIL_V1_OPERATION_QUERY_KEYS,
    NPM_PUBLIC_REGISTRY_HOST,
    NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT,
    NPM_PUBLIC_REGISTRY_RECEIPT_FIELDS,
    PolicyBundleError,
    X_V2_RECENT_SEARCH_PATHS,
    adapter_operation_field_names,
    bounded_pattern_matches,
    canonical_json,
    is_serverware_internal_header,
    provider_request_profile,
    strict_json_loads,
    validate_buffered_json_passthrough_request,
    validate_buffered_passthrough_response,
    validate_raw_absolute_target,
    validated_request_urlsplit,
)


OLDER_THAN_RE = re.compile(r"\bolder_than:(\d+)([dmy])\b", re.IGNORECASE)
NEWER_THAN_RE = re.compile(r"\bnewer_than:(\d+)([dmy])\b", re.IGNORECASE)
_GENERIC_NON_FORWARDED_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-serverware-agent",
    "x-serverware-data-plane-token",
}
_STREAMING_RESPONSE_MODES = {
    "stream",
    "jsonlStream",
    "jsonArrayStream",
    "jsonSseStream",
    "jsonNestedStream",
    "formUrlencodedStream",
    "csvStream",
}
_STRUCTURED_STREAMING_MODES = _STREAMING_RESPONSE_MODES - {"stream"}
_PROJECTED_RESPONSE_MODES = {"json"} | _STRUCTURED_STREAMING_MODES
_WHOLE_JSON_RESPONSE_MODES = {
    BUFFERED_PASSTHROUGH_RESPONSE_MODE,
    BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE,
}
_BUFFERED_REQUEST_CONSTRAINTS = {
    "json": "jsonBody",
    "formUrlencoded": "formBody",
}
_SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "content-language",
    "etag",
    "last-modified",
    "retry-after",
    "www-authenticate",
}
_RESPONSE_CONTENT_TYPES = {
    "json": "application/json",
    BUFFERED_PASSTHROUGH_RESPONSE_MODE: "application/json",
    BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE: "application/json",
    "jsonlStream": "application/x-ndjson",
    "jsonArrayStream": "application/json",
    "jsonSseStream": "text/event-stream",
    "jsonNestedStream": "application/json",
    "formUrlencodedStream": "application/x-www-form-urlencoded",
    "csvStream": "text/csv",
}
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_HTTP_TOKEN_PATTERN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_CONTENT_TYPE_RE = re.compile(
    rf"^[ \t]*({_HTTP_TOKEN_PATTERN})/({_HTTP_TOKEN_PATTERN})"
    rf"(?:[ \t]*;[ \t]*{_HTTP_TOKEN_PATTERN}[ \t]*=[ \t]*"
    rf'(?:{_HTTP_TOKEN_PATTERN}|"(?:[\t !#-\[\]-~]|\\[\t -~])*")'
    rf")*[ \t]*$"
)
_RESPONSE_FIELD_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
_OPERATION_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_JSON_OPERATION_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
_GMAIL_PROOF_NONCE_HEADER = "x-serverware-proof-nonce"
_GMAIL_STREAM_PROOF_NONCE_HEADER = "x-serverware-stream-proof-nonce"
_MIN_GMAIL_CHILD_AUTHORITY_SECONDS = 0.250
_GMAIL_INTERNAL_DATE_FUTURE_SKEW_MS = 5 * 60 * 1000
_MAX_NPM_ATTACHMENT_BYTES = 16 * 1024 * 1024
_BUFFERED_JSON_MAX_CONTAINER_DEPTH = 127


def _strict_buffered_json(raw: bytes) -> Any:
    """Inspect new whole-JSON modes without rewriting their wire bytes."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > _BUFFERED_JSON_MAX_CONTAINER_DEPTH:
                raise ValueError("buffered JSON container depth exceeded")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            if depth < 0:
                raise ValueError("buffered JSON container nesting is invalid")
    payload = strict_json_loads(raw)
    # The raw-byte limit bounds nodes and decoded text. Iterator frames use only
    # O(depth) additional storage; no serialized copy becomes the dispatched body.
    pending = [iter((payload,))]
    while pending:
        try:
            value = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        if isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, dict):
            for key in value:
                key.encode("utf-8")
            pending.append(iter(value.values()))
        elif isinstance(value, list):
            pending.append(iter(value))
    return payload


def _parse_content_type(value: str) -> str | None:
    """Return a canonical media type after rejecting ambiguous parameters."""
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    match = _CONTENT_TYPE_RE.fullmatch(value) if 0 < len(encoded) <= 8192 else None
    if match is None:
        return None

    separator = value.find(";", match.end(2))
    if separator < 0:
        return f"{match.group(1)}/{match.group(2)}".lower()
    parameters = value[separator:]
    seen: set[str] = set()
    index = 0
    while index < len(parameters):
        while index < len(parameters) and parameters[index] in " \t":
            index += 1
        if index >= len(parameters):
            break
        if parameters[index] != ";":
            return None
        index += 1
        while index < len(parameters) and parameters[index] in " \t":
            index += 1
        name_start = index
        while (
            index < len(parameters)
            and re.fullmatch(_HTTP_TOKEN_PATTERN, parameters[index]) is not None
        ):
            index += 1
        name = parameters[name_start:index].lower()
        if not name or name in seen:
            return None
        seen.add(name)
        while index < len(parameters) and parameters[index] in " \t":
            index += 1
        if index >= len(parameters) or parameters[index] != "=":
            return None
        index += 1
        while index < len(parameters) and parameters[index] in " \t":
            index += 1
        if index >= len(parameters):
            return None
        if parameters[index] == '"':
            index += 1
            closed = False
            while index < len(parameters):
                if parameters[index] == "\\":
                    index += 2
                    continue
                if parameters[index] == '"':
                    index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                return None
        else:
            value_start = index
            while (
                index < len(parameters)
                and re.fullmatch(_HTTP_TOKEN_PATTERN, parameters[index]) is not None
            ):
                index += 1
            if index == value_start:
                return None
    return f"{match.group(1)}/{match.group(2)}".lower()


def _secure_bounded_metadata_get(
    *,
    origin: str,
    path: str,
    headers: dict[str, str],
    timeout_seconds: float,
    max_body_bytes: int,
    deadline: http_client.HttpDeadline,
) -> Any:
    del origin, path, headers, timeout_seconds, max_body_bytes, deadline
    raise http_client.HttpClientError(
        "Gmail metadata hydration is disabled because an explicit child "
        "credential reservation and audit claim are unavailable"
    )


def _buffered_json_request_policy_error(
    route: Any, *, adapter_type: str | None = None
) -> PolicyDecision | None:
    try:
        validate_buffered_json_passthrough_request(
            str(getattr(route, "id", "runtime")),
            adapter_type or getattr(route, "adapter_type", "generic.rest"),
            route.adapter_config.get("request"),
            tuple(getattr(route, "constraints", ()) or ()),
        )
    except PolicyBundleError:
        return PolicyDecision(
            allowed=False,
            status_code=500,
            reason="buffered JSON request policy is invalid",
            payload={"error": "request_json_passthrough_policy_invalid"},
        )
    return None


def preflight_request_admission(
    flow: Any,
    route: Any,
    normalized_headers: dict[str, str],
) -> PolicyDecision:
    """Apply pure bounded byte-level checks before any adapter parser runs."""
    request_cfg = (
        route.adapter_config.get("request")
        if isinstance(route.adapter_config, dict)
        else None
    )
    if not isinstance(request_cfg, dict):
        return PolicyDecision(
            allowed=False,
            status_code=500,
            reason="request policy is missing",
            payload={"error": "request_policy_missing"},
        )
    passthrough_error = _buffered_json_request_policy_error(route)
    if passthrough_error is not None:
        return passthrough_error
    max_body_bytes = request_cfg.get("maxBodyBytes")
    if (
        type(max_body_bytes) is not int
        or max_body_bytes < 0
    ):
        return PolicyDecision(
            allowed=False,
            status_code=500,
            reason="request body limit is missing or invalid",
            payload={"error": "request_body_limit_invalid"},
        )

    try:
        raw_body = flow.request.raw_content
    except Exception:
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request body bytes are unavailable",
            payload={"error": "request_body_unavailable"},
        )
    if not isinstance(raw_body, bytes):
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request body is not buffered bytes",
            payload={"error": "request_body_not_buffered"},
        )
    body = raw_body

    if "transfer-encoding" in normalized_headers:
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request transfer framing is not allowed",
            payload={"error": "request_transfer_encoding_denied"},
        )
    content_length = normalized_headers.get("content-length")
    if content_length is not None:
        if (
            len(content_length) > 20
            or re.fullmatch(r"[0-9]+", content_length) is None
        ):
            return PolicyDecision(
                allowed=False,
                status_code=400,
                reason="request Content-Length is malformed",
                payload={"error": "request_content_length_invalid"},
            )
        if int(content_length) != len(body):
            return PolicyDecision(
                allowed=False,
                status_code=400,
                reason="request Content-Length does not match the buffered body",
                payload={"error": "request_content_length_mismatch"},
            )

    if len(body) > max_body_bytes:
        return PolicyDecision(
            allowed=False,
            status_code=413,
            reason="request body exceeded policy limit",
            payload={
                "error": "request_body_too_large",
                "maxBodyBytes": max_body_bytes,
            },
        )

    body_mode = request_cfg.get("bodyMode")
    if (body_mode == "none" or max_body_bytes == 0) and body:
        return PolicyDecision(
            allowed=False,
            status_code=403,
            reason="request body is forbidden by policy",
            payload={"error": "request_body_not_allowed"},
        )

    content_encoding = normalized_headers.get("content-encoding")
    if content_encoding is not None and content_encoding != "identity":
        return PolicyDecision(
            allowed=False,
            status_code=415,
            reason="encoded request bodies are not supported",
            payload={"error": "request_content_encoding_denied"},
        )

    content_type = normalized_headers.get("content-type")
    media_type: str | None = None
    if content_type is not None:
        media_type = _parse_content_type(content_type)
        if media_type is None:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason="request Content-Type is malformed",
                payload={"error": "request_content_type_denied"},
            )

    expected_media_types: set[str] | None = None
    raw_allowed_media_types = request_cfg.get("allowedMediaTypes")
    if raw_allowed_media_types is not None:
        if (
            not isinstance(raw_allowed_media_types, list)
            or any(
                not isinstance(value, str)
                or _MEDIA_TYPE_RE.fullmatch(value) is None
                for value in raw_allowed_media_types
            )
        ):
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="request media-type policy is invalid",
                payload={"error": "request_media_type_policy_invalid"},
            )
        expected_media_types = {
            value.lower() for value in raw_allowed_media_types
        }
    elif body_mode == "json":
        expected_media_types = {"application/json"}
    elif body_mode == "formUrlencoded":
        expected_media_types = {"application/x-www-form-urlencoded"}

    if expected_media_types is not None:
        if media_type is None and body:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason="request Content-Type is required for a body",
                payload={"error": "request_content_type_required"},
            )
        if media_type is not None and media_type not in expected_media_types:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason="request Content-Type is not allowed by policy",
                payload={
                    "error": (
                        "request_json_content_type_denied"
                        if body_mode == "json"
                        else "request_form_content_type_denied"
                        if body_mode == "formUrlencoded"
                        else "request_content_type_denied"
                    ),
                    "contentType": media_type,
                },
            )

    get_content = getattr(flow.request, "get_content", None)
    if not callable(get_content):
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request body access is unavailable",
            payload={"error": "request_body_unavailable"},
        )
    try:
        decoded_body = get_content(strict=True)
    except Exception:
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request body access failed",
            payload={"error": "request_body_unavailable"},
        )
    if not isinstance(decoded_body, bytes) or decoded_body != body:
        return PolicyDecision(
            allowed=False,
            status_code=400,
            reason="request body access did not preserve the buffered bytes",
            payload={"error": "request_body_unavailable"},
        )
    return PolicyDecision(allowed=True)


class ApiAdapter:
    id = "generic.rest"

    def validate_credential_metadata(
        self,
        route: Any,
        metadata: dict[str, Any] | None,
    ) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def validate_credential(self, route: Any, credential: dict[str, Any] | None) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def _validate_provider_request_profile(self, flow: Any, route: Any) -> PolicyDecision:
        request_cfg = route.adapter_config.get("request")
        try:
            expected = provider_request_profile(
                self.id,
                str(route.adapter_config.get("mode") or ""),
            )
        except Exception:
            expected = None
        valid_lists = isinstance(request_cfg, dict) and isinstance(expected, dict)
        if valid_lists:
            for field_name in (
                "allowedHeaders",
                "allowedQueryKeys",
                "allowedMediaTypes",
            ):
                values = request_cfg.get(field_name)
                expected_values = expected.get(field_name)
                if (
                    not isinstance(values, list)
                    or any(not isinstance(value, str) for value in values)
                    or len(values) != len(set(values))
                    or set(values) != set(expected_values or [])
                ):
                    valid_lists = False
                    break
        discard_headers = (
            request_cfg.get("discardHeaders", [])
            if isinstance(request_cfg, dict)
            else None
        )
        if (
            valid_lists
            and (
                not isinstance(discard_headers, list)
                or any(not isinstance(value, str) for value in discard_headers)
                or len(discard_headers) != len(set(discard_headers))
            )
        ):
            valid_lists = False
        value_rules = (
            request_cfg.get("valueRules")
            if isinstance(request_cfg, dict)
            else None
        )
        if (
            valid_lists
            and (
                not isinstance(value_rules, list)
                or len(value_rules) > 32
                or any(not isinstance(rule, dict) for rule in value_rules)
            )
        ):
            valid_lists = False
        expected_fields = set(expected or {})
        required_fields = expected_fields - {"discardHeaders"}
        required_discard_headers = set(
            (expected or {}).get("discardHeaders") or []
        )
        if (
            not isinstance(request_cfg, dict)
            or not required_fields.issubset(request_cfg)
            or not set(request_cfg).issubset(expected_fields)
            or not valid_lists
            or (
                bool(required_discard_headers)
                and (
                    "discardHeaders" not in request_cfg
                    or not required_discard_headers.issubset(
                        discard_headers or []
                    )
                )
            )
            or type(request_cfg.get("maxBodyBytes")) is not int
            or request_cfg.get("maxBodyBytes") != (expected or {}).get("maxBodyBytes")
        ):
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason=f"{self.id} request profile is invalid",
                payload={"error": "provider_request_profile_invalid", "adapter": self.id},
            )

        allowed_headers = set(request_cfg["allowedHeaders"])
        for raw_name in getattr(flow.request, "headers", {}):
            name = str(raw_name).strip().lower()
            if name in _GENERIC_NON_FORWARDED_HEADERS or is_serverware_internal_header(name):
                continue
            # Content-Type is reserved for the exact media/physical-field checks below,
            # not an ordinary configurable provider request header.
            if name != "content-type" and name not in allowed_headers:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"{self.id} request header is not allowed by policy: {name}",
                    payload={"error": "request_header_not_allowed", "header": name},
                )

        allowed_query_keys = set(request_cfg["allowedQueryKeys"])
        for key, _ in parse_qsl(
            validated_request_urlsplit(flow.request.pretty_url).query,
            keep_blank_values=True,
        ):
            if key not in allowed_query_keys:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"{self.id} request contains a query key not allowed by policy",
                    payload={"error": "request_query_key_not_allowed", "queryKey": key},
                )

        body = flow.request.raw_content or b""
        max_body_bytes = request_cfg["maxBodyBytes"]
        if body and max_body_bytes == 0:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"{self.id} request body is forbidden by policy",
                payload={"error": "request_body_not_allowed"},
            )
        if len(body) > max_body_bytes:
            return PolicyDecision(
                allowed=False,
                status_code=413,
                reason=f"{self.id} request body exceeded policy limit",
                payload={"error": "request_body_too_large", "maxBodyBytes": max_body_bytes},
            )

        content_types = self._response_header_values(flow.request.headers, "content-type")
        if not content_types:
            if body:
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason=f"{self.id} request Content-Type is required for a body",
                    payload={"error": "request_content_type_required"},
                )
            return PolicyDecision(allowed=True)
        if len(content_types) != 1:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason=f"{self.id} request Content-Type must occur exactly once",
                payload={"error": "request_content_type_ambiguous"},
            )
        media_type = _parse_content_type(content_types[0])
        if media_type is None:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason=f"{self.id} request Content-Type is malformed",
                payload={"error": "request_content_type_denied"},
            )
        if media_type not in set(request_cfg["allowedMediaTypes"]):
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason=f"{self.id} request Content-Type is not allowed by policy",
                payload={"error": "request_content_type_denied"},
            )
        return PolicyDecision(allowed=True)

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        request_cfg = route.adapter_config.get("request") or {}
        if not request_cfg:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic request policy is missing",
                payload={"error": "generic_request_policy_missing"},
            )
        passthrough_error = _buffered_json_request_policy_error(
            route, adapter_type=self.id
        )
        if passthrough_error is not None:
            return passthrough_error
        credential_mode = route.adapter_config.get("credentialMode")
        if getattr(route, "credential_ref", None):
            if (
                credential_mode != "required"
                or not isinstance(
                    route.adapter_config.get("credentialBinding"), dict
                )
                or "noCredentialProof" in route.adapter_config
            ):
                return PolicyDecision(
                    allowed=False,
                    status_code=500,
                    reason="generic credential binding is invalid",
                    payload={"error": "generic_credential_binding_invalid"},
                )
        elif (
            credential_mode != "none"
            or "credentialBinding" in route.adapter_config
            or route.adapter_config.get("noCredentialProof")
            != {
                "credentialRefAbsent": True,
                "secretInjectionDisabled": True,
                "sensitiveHeadersForwarded": False,
                "authorizationForwarded": False,
            }
        ):
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic no-credential proof is invalid",
                payload={"error": "generic_no_credential_proof_invalid"},
            )

        allowed_headers = {str(item).strip().lower() for item in request_cfg.get("allowedHeaders") or []}
        required_headers = request_cfg.get("requiredHeaders") or {}
        if not isinstance(required_headers, dict):
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic required header policy is invalid",
                payload={"error": "generic_required_headers_invalid"},
            )
        for name, rule in required_headers.items():
            value = self._header_value(flow.request.headers, str(name))
            if value is None:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"generic required request header is missing: {name}",
                    payload={"error": "required_header_missing", "header": name},
                )
            if not isinstance(rule, dict):
                return PolicyDecision(
                    allowed=False,
                    status_code=500,
                    reason=f"generic required request header policy is invalid: {name}",
                    payload={"error": "required_header_policy_invalid", "header": name},
                )
            minimum = rule.get("minLength")
            maximum = rule.get("maxLength")
            pattern = rule.get("pattern")
            encoded_length = len(str(value).encode("utf-8"))
            pattern_match = bounded_pattern_matches(pattern, str(value)) if isinstance(pattern, str) else True
            if (
                rule.get("type") != "string"
                or type(minimum) is not int
                or type(maximum) is not int
                or not minimum <= encoded_length <= maximum
                or pattern_match is not True
            ):
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"generic required request header is invalid: {name}",
                    payload={"error": "required_header_invalid", "header": name},
                )
        for raw_name in getattr(flow.request, "headers", {}):
            name = str(raw_name).strip().lower()
            if name in _GENERIC_NON_FORWARDED_HEADERS or is_serverware_internal_header(name):
                continue
            # Content-Type is mediated by the physical-header and media-type
            # checks below, not by the agent-forwardable header allowlist.
            if name == "content-type":
                continue
            if name not in allowed_headers:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"generic request header is not allowed by policy: {name}",
                    payload={"error": "request_header_not_allowed", "header": name},
                )

        allowed_query_keys = {str(item) for item in request_cfg.get("allowedQueryKeys") or []}
        for key, _ in parse_qsl(
            validated_request_urlsplit(flow.request.pretty_url).query,
            keep_blank_values=True,
        ):
            if key not in allowed_query_keys:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason="generic request contains a query key not allowed by policy",
                    payload={"error": "request_query_key_not_allowed", "queryKey": key},
                )

        body = flow.request.raw_content or b""
        if (
            request_cfg.get("bodyMode") == BUFFERED_JSON_PASSTHROUGH_REQUEST_MODE
            and not isinstance(flow.request.raw_content, bytes)
        ):
            return PolicyDecision(
                allowed=False,
                status_code=400,
                reason="request body is not buffered bytes",
                payload={"error": "request_body_not_buffered"},
            )
        max_body = request_cfg.get("maxBodyBytes")
        if max_body is None:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="generic request body limit is missing",
                payload={"error": "generic_request_body_limit_missing"},
            )
        if len(body) > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=413,
                reason="generic request body exceeded policy limit",
                payload={"error": "request_body_too_large", "maxBodyBytes": int(max_body)},
            )

        content_types = self._response_header_values(
            flow.request.headers,
            "content-type",
        )
        if not content_types:
            if body:
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic request Content-Type is required for a body",
                    payload={"error": "request_content_type_required"},
                )
        elif len(content_types) != 1:
            return PolicyDecision(
                allowed=False,
                status_code=415,
                reason="generic request Content-Type must occur exactly once",
                payload={"error": "request_content_type_ambiguous"},
            )
        else:
            media_type = _parse_content_type(content_types[0])
            if media_type is None:
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic request Content-Type is malformed",
                    payload={"error": "request_content_type_denied"},
                )
            allowed_media_types = request_cfg.get("allowedMediaTypes")
            if (
                not isinstance(allowed_media_types, list)
                or media_type not in set(allowed_media_types)
            ):
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic request Content-Type is not allowed by policy",
                    payload={"error": "request_content_type_denied"},
                )

        body_mode = request_cfg.get("bodyMode")
        if body_mode in _STRUCTURED_STREAMING_MODES:
            projection_error = self._request_projection_error(request_cfg, str(body_mode))
            if projection_error is not None:
                return projection_error
        body_policy_error = self._credential_request_body_policy_error(route, body_mode)
        if body_policy_error is not None:
            return body_policy_error
        if body_mode == "none" and body:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="generic request body is forbidden by policy",
                payload={"error": "request_body_not_allowed"},
            )
        if body_mode in {"json", BUFFERED_JSON_PASSTHROUGH_REQUEST_MODE} and body:
            content_type = str(flow.request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic JSON request has an unsupported content type",
                    payload={"error": "request_json_content_type_denied", "contentType": content_type},
                )
            try:
                if body_mode == BUFFERED_JSON_PASSTHROUGH_REQUEST_MODE:
                    _strict_buffered_json(body)
                else:
                    strict_json_loads(body)
            except Exception:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason="generic JSON request body is invalid",
                    payload={"error": "request_json_invalid"},
                )
        if body_mode == "formUrlencoded" and body:
            content_type = str(flow.request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/x-www-form-urlencoded":
                return PolicyDecision(
                    allowed=False,
                    status_code=415,
                    reason="generic form request has an unsupported content type",
                    payload={"error": "request_form_content_type_denied", "contentType": content_type},
                )
            try:
                self._parse_form_urlencoded(body)
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason=str(exc),
                    payload={"error": "request_form_invalid"},
                )
        return PolicyDecision(allowed=True)

    @staticmethod
    def _header_value(headers: Any, name: str) -> str | None:
        value = headers.get(name)
        if value is not None:
            return str(value)
        lower = name.lower()
        for raw_name, candidate in getattr(headers, "items", lambda: [])():
            if str(raw_name).lower() == lower:
                return str(candidate)
        return None

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        request_cfg = route.adapter_config.get("request") or {}
        passthrough_error = _buffered_json_request_policy_error(
            route, adapter_type=self.id
        )
        if passthrough_error is not None:
            return passthrough_error
        # bufferedJsonPassthroughV1 has no body rewrite: strict admission happens
        # before authorization and the existing digest binds the exact raw bytes.
        if request_cfg.get("bodyMode") in _STRUCTURED_STREAMING_MODES:
            projection_error = self._request_projection_error(
                request_cfg,
                str(request_cfg.get("bodyMode")),
            )
            if projection_error is not None:
                return projection_error
            allowed_fields = self._allowed_field_paths(request_cfg)
            try:
                if request_cfg.get("bodyMode") == "jsonArrayStream":
                    flow.request.content = self._redact_json_array(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "jsonSseStream":
                    flow.request.content = self._redact_json_sse(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "jsonNestedStream":
                    flow.request.content = self._redact_json_nested(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "formUrlencodedStream":
                    flow.request.content = self._redact_form_urlencoded(flow.request.raw_content or b"", allowed_fields)
                elif request_cfg.get("bodyMode") == "csvStream":
                    flow.request.content = self._redact_csv(flow.request.raw_content or b"", allowed_fields)
                else:
                    flow.request.content = self._redact_json_lines(flow.request.raw_content or b"", allowed_fields)
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason=str(exc),
                    payload={"error": "streaming_redaction_request_invalid", "detail": str(exc)},
                )
        return PolicyDecision(allowed=True)

    def _credential_request_body_policy_error(
        self,
        route: Any,
        body_mode: Any,
    ) -> PolicyDecision | None:
        if not getattr(route, "credential_ref", None):
            return None
        if body_mode in {"any", "stream"}:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason=(
                    "credential-bearing generic requests cannot use opaque "
                    f"bodyMode {body_mode}"
                ),
                payload={
                    "error": "credential_opaque_request_body_denied",
                    "adapter": self.id,
                    "bodyMode": body_mode,
                },
            )
        required_constraint = _BUFFERED_REQUEST_CONSTRAINTS.get(str(body_mode))
        if required_constraint is None:
            return None
        constraints = getattr(route, "constraints", ()) or ()
        if any(
            isinstance(constraint, dict)
            and constraint.get("type") == required_constraint
            and (constraint.get("phase") or "request") == "request"
            and isinstance(constraint.get("allowedFields"), list)
            and bool(constraint["allowedFields"])
            for constraint in constraints
        ):
            return None
        return PolicyDecision(
            allowed=False,
            status_code=500,
            reason=(
                f"credential-bearing generic request bodyMode {body_mode} requires "
                f"a {required_constraint} constraint with non-empty allowedFields"
            ),
            payload={
                "error": "credential_request_body_policy_missing",
                "adapter": self.id,
                "bodyMode": body_mode,
                "requiredConstraint": required_constraint,
            },
        )

    def _request_projection_error(
        self,
        request_cfg: dict[str, Any],
        mode: str,
    ) -> PolicyDecision | None:
        fields = request_cfg.get("allowedFields")
        if fields is None or fields == []:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="streaming redaction request policy missing allowedFields",
                payload={"error": "streaming_redaction_request_allowed_fields_missing"},
            )
        if (
            not isinstance(fields, list)
            or len(fields) > 64
            or any(
                not isinstance(field, str)
                or len(field) > 256
                or _RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
                for field in fields
            )
            or len(fields) != len(set(fields))
        ):
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="streaming redaction request policy allowedFields is invalid",
                payload={
                    "error": "streaming_redaction_request_allowed_fields_invalid",
                    "mode": mode,
                },
            )
        return None

    def prepare_response(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
        *,
        authorization_factory: Callable[[], tuple[str, float]] | None = None,
    ) -> PolicyDecision:
        if not flow.response:
            return PolicyDecision(allowed=True)
        passthrough_error = self._buffered_passthrough_policy_error(route)
        if passthrough_error is not None:
            return passthrough_error
        response_cfg, profile_error = self._response_profile(flow, route)
        if (
            profile_error is not None
            and (route.adapter_config.get("response") or {}).get("mode")
            == BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE
        ):
            return profile_error
        if response_cfg is not None and response_cfg.get("mode") in {"json"} | _WHOLE_JSON_RESPONSE_MODES:
            media_type_error = self._json_response_body_contract_error(flow, response_cfg)
            if media_type_error is not None:
                return media_type_error
        return PolicyDecision(allowed=True)

    def validate_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if not flow.response:
            return PolicyDecision(allowed=True)
        passthrough_error = self._buffered_passthrough_policy_error(route)
        if passthrough_error is not None:
            return passthrough_error
        response_cfg, profile_error = self._response_profile(flow, route)
        if profile_error is not None:
            return profile_error
        assert response_cfg is not None
        if response_cfg.get("mode") in {"json"} | _WHOLE_JSON_RESPONSE_MODES:
            media_type_error = self._json_response_body_contract_error(flow, response_cfg)
            if media_type_error is not None:
                return media_type_error
        max_body = response_cfg.get("maxBodyBytes")
        if max_body is None:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="response body limit is missing",
                payload={"error": "response_body_limit_missing"},
            )
        if len(flow.response.raw_content or b"") > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="generic response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": int(max_body)},
            )
        mode = response_cfg.get("mode")
        supported_modes = {"any", "headersOnly", "json"} | _STREAMING_RESPONSE_MODES
        if self.id == "generic.rest":
            supported_modes.update(_WHOLE_JSON_RESPONSE_MODES)
        if mode not in supported_modes:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="unsupported response mode",
                payload={"error": "response_mode_unsupported", "mode": mode},
            )
        if route.credential_ref and mode in {"any", "stream"}:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="credential-bearing response requires structured projection",
                payload={"error": "credential_response_projection_required", "mode": mode},
            )
        if mode == BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE and flow.response.status_code == 204:
            # The body/framing contract was checked above; do not manufacture a
            # JSON value or assign content (the HTTP object may synthesize CL).
            # Engine envelope/semantic and final release guards still run.
            self._normalize_response_headers(flow, response_cfg, mode)
            return PolicyDecision(allowed=True)
        if mode == "headersOnly":
            flow.response.content = b""
            self._normalize_response_headers(flow, response_cfg, mode)
            return PolicyDecision(allowed=True)
        if mode in _PROJECTED_RESPONSE_MODES:
            projection_error = self._response_projection_error(
                response_cfg,
                mode,
                credential_bearing=bool(getattr(route, "credential_ref", None)),
            )
            if projection_error is not None:
                return projection_error
        allowed_fields = self._allowed_field_paths(response_cfg)
        if mode in {"jsonlStream", "jsonArrayStream", "jsonSseStream", "jsonNestedStream", "formUrlencodedStream", "csvStream"}:
            try:
                if mode == "jsonArrayStream":
                    flow.response.content = self._redact_json_array(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/json"
                elif mode == "jsonSseStream":
                    flow.response.content = self._redact_json_sse(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "text/event-stream"
                elif mode == "jsonNestedStream":
                    flow.response.content = self._redact_json_nested(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/json"
                elif mode == "formUrlencodedStream":
                    flow.response.content = self._redact_form_urlencoded(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/x-www-form-urlencoded"
                elif mode == "csvStream":
                    flow.response.content = self._redact_csv(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "text/csv"
                else:
                    flow.response.content = self._redact_json_lines(flow.response.raw_content or b"", allowed_fields)
                    flow.response.headers["Content-Type"] = "application/x-ndjson"
            except ValueError as exc:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason=str(exc),
                    payload={"error": "streaming_redaction_response_invalid", "detail": str(exc)},
                )
            self._normalize_response_headers(flow, response_cfg, mode)
            return PolicyDecision(allowed=True)
        if mode in {"json"} | _WHOLE_JSON_RESPONSE_MODES or allowed_fields:
            try:
                raw_body = flow.response.raw_content or b""
                payload = (
                    _strict_buffered_json(raw_body)
                    if mode == BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE
                    else strict_json_loads(raw_body)
                )
            except Exception:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="response is not valid JSON",
                    payload={"error": "response_invalid_json"},
                )
            if allowed_fields:
                payload = self._redact_json(payload, allowed_fields)
            if mode in _WHOLE_JSON_RESPONSE_MODES:
                try:
                    inspection = json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                except (TypeError, ValueError, UnicodeError, RecursionError):
                    return PolicyDecision(
                        allowed=False,
                        status_code=502,
                        reason="response JSON inspection serialization failed",
                        payload={"error": "response_serialization_failed"},
                    )
                if len(inspection) > int(max_body):
                    return PolicyDecision(
                        allowed=False,
                        status_code=502,
                        reason="normalized response inspection exceeded policy limit",
                        payload={"error": "response_inspection_body_too_large", "maxBodyBytes": int(max_body)},
                    )
                # The prototype has no credential-bearing forwarding authority.
                # Rust additionally scans this decoded representation for secrets.
                # Preserve the received bytes: JSON serialization can round numbers.
                self._normalize_response_headers(flow, response_cfg, mode)
                return PolicyDecision(allowed=True)
            flow.response.headers["Content-Type"] = "application/json"
            flow.response.set_text(canonical_json(payload))
        self._normalize_response_headers(flow, response_cfg, mode)
        return PolicyDecision(allowed=True)

    def finalize_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        return PolicyDecision(allowed=True)

    def _buffered_passthrough_policy_error(self, route: Any) -> PolicyDecision | None:
        try:
            validate_buffered_passthrough_response(
                str(getattr(route, "id", "runtime")),
                self.id if self.id != "generic.rest" else getattr(route, "adapter_type", self.id),
                route.adapter_config.get("response"),
                tuple(getattr(route, "constraints", ()) or ()),
            )
        except PolicyBundleError:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="buffered passthrough response policy is invalid",
                payload={"error": "response_passthrough_policy_invalid"},
            )
        return None

    def _response_profile(
        self, flow: Any, route: Any
    ) -> tuple[dict[str, Any] | None, PolicyDecision | None]:
        status_code = int(flow.response.status_code)
        response_cfg = route.adapter_config.get("response") or {}
        if 200 <= status_code < 300:
            if (
                response_cfg.get("mode") == BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE
                and not self._response_envelope_admits_status(flow, route, status_code)
            ):
                return None, PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="provider success status is outside the explicit response envelope",
                    payload={"error": "response_envelope_status_denied"},
                )
            if response_cfg:
                return response_cfg, None
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="response policy is missing",
                payload={"error": "response_policy_missing"},
            )
        if 300 <= status_code < 400:
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="provider redirects are not allowed by policy",
                payload={"error": "response_redirect_not_allowed", "upstreamStatus": status_code},
            )
        if 400 <= status_code < 600:
            error_cfg = response_cfg.get("error")
            if (
                isinstance(error_cfg, dict)
                and error_cfg
                and self._response_envelope_admits_status(flow, route, status_code)
            ):
                return error_cfg, None
            return None, PolicyDecision(
                allowed=False,
                status_code=502,
                reason="provider error status is outside the explicit policy/profile intersection",
                payload={
                    "error": "response_error_profile_status_denied",
                    "upstreamStatus": status_code,
                },
            )
        return None, PolicyDecision(
            allowed=False,
            status_code=502,
            reason="provider returned an invalid response status",
            payload={"error": "response_status_invalid", "upstreamStatus": status_code},
        )

    @staticmethod
    def _response_envelope_admits_status(
        flow: Any,
        route: Any,
        status_code: int,
    ) -> bool:
        operation_fields = flow.metadata.get("serverware_operation") or {}
        operation = (
            operation_fields.get("operation")
            if isinstance(operation_fields, dict)
            else None
        )
        applicable = [
            constraint
            for constraint in (getattr(route, "constraints", ()) or ())
            if isinstance(constraint, dict)
            and constraint.get("type") == "responseEnvelope"
            and (
                not constraint.get("operations")
                or operation in (constraint.get("operations") or [])
            )
        ]
        return bool(applicable) and all(
            status_code in (constraint.get("statusCodes") or [])
            for constraint in applicable
        )

    @staticmethod
    def _response_header_values(headers: Any, name: str) -> list[str]:
        get_all = getattr(headers, "get_all", None)
        if callable(get_all):
            values = get_all(name)
            return [str(value) for value in (values or [])]
        lower = name.lower()
        return [
            str(value)
            for raw_name, value in getattr(headers, "items", lambda: [])()
            if str(raw_name).lower() == lower
        ]

    def _json_response_media_type_error(self, flow: Any) -> PolicyDecision | None:
        values = self._response_header_values(flow.response.headers, "content-type")
        valid = False
        if len(values) == 1:
            try:
                encoded_value = values[0].encode("utf-8")
            except UnicodeEncodeError:
                encoded_value = b""
            if encoded_value and len(encoded_value) <= 8192:
                valid = _parse_content_type(values[0]) == "application/json"
        if valid:
            return None
        return PolicyDecision(
            allowed=False,
            status_code=502,
            reason="upstream JSON response Content-Type is invalid",
            payload={"error": "response_json_content_type_denied"},
        )

    def _json_response_body_contract_error(
        self, flow: Any, response_cfg: dict[str, Any]
    ) -> PolicyDecision | None:
        if response_cfg.get("mode") != BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE:
            return self._json_response_media_type_error(flow)
        if not isinstance(flow.response.raw_content, bytes):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="upstream response body bytes are unavailable",
                payload={"error": "response_envelope_body_unavailable"},
            )
        if flow.response.status_code != 204:
            return self._json_response_media_type_error(flow)
        # Validate only evidence the HTTP implementation exposes. This is not a
        # claim that bytes hidden beyond HTTP's bodyless framing are observable.
        raw_body = flow.response.raw_content
        trailers = getattr(flow.response, "trailers", None)
        if (
            raw_body
            or self._response_header_values(flow.response.headers, "content-length")
            or self._response_header_values(flow.response.headers, "transfer-encoding")
            or trailers
        ):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="upstream 204 response body or framing is invalid",
                payload={"error": "response_empty_204_invalid"},
            )
        if self._response_header_values(flow.response.headers, "content-type"):
            return self._json_response_media_type_error(flow)
        return None

    def _normalize_response_headers(
        self, flow: Any, response_cfg: dict[str, Any], mode: str
    ) -> None:
        released: dict[str, str] = {}
        configured = {
            str(name).strip().lower() for name in (response_cfg.get("allowedHeaders") or [])
        }
        for name in sorted(configured & _SAFE_RESPONSE_HEADERS):
            value = flow.response.headers.get(name)
            if value is None:
                continue
            text = str(value)
            if len(text.encode("utf-8")) <= 8192 and "\r" not in text and "\n" not in text:
                released[name] = text

        empty_204 = (
            mode == BUFFERED_JSON_OR_EMPTY_204_RESPONSE_MODE
            and flow.response.status_code == 204
        )
        content_type = (
            self._header_value(flow.response.headers, "content-type")
            if empty_204
            else _RESPONSE_CONTENT_TYPES.get(mode)
        )
        if content_type is None and mode in {"any", "stream"}:
            upstream_type = str(flow.response.headers.get("content-type") or "")
            media_type = upstream_type.split(";", 1)[0].strip().lower()
            content_type = media_type if _MEDIA_TYPE_RE.fullmatch(media_type) else "application/octet-stream"

        flow.response.headers.clear()
        if content_type and mode != "headersOnly":
            flow.response.headers["Content-Type"] = content_type
        for name, value in released.items():
            flow.response.headers[name] = value
        if not empty_204:
            flow.response.headers["Content-Length"] = str(len(flow.response.raw_content or b""))

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        if any(
            isinstance(constraint, dict) and constraint.get("type") == "requestValue"
            for constraint in (getattr(route, "constraints", ()) or ())
        ):
            flow.metadata["serverware_request_value_path_params"] = {
                str(name): value
                for name, value in params.items()
                if isinstance(value, str)
            }
        request_config = route.adapter_config.get("request") or {}
        operation = request_config.get("operation") or {}
        name = operation.get("name")
        fields: dict[str, str] = {"operation": str(name)} if name else {}

        for field in operation.get("pathParams") or []:
            value = params.get(str(field))
            if isinstance(value, str):
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError:
                    continue
                fields[str(field)] = value

        configured_form_fields = {str(item) for item in operation.get("formFields") or []}
        if configured_form_fields:
            try:
                pairs = self._parse_form_urlencoded(flow.request.raw_content or b"")
            except ValueError:
                pairs = []
            values: dict[str, list[str]] = {}
            for key, value in pairs:
                normalized = self._normalized_form_key(key)
                if normalized in configured_form_fields:
                    values.setdefault(normalized, []).append(value)
            for field, found in values.items():
                if len(found) == 1:
                    fields[field] = found[0]

        configured_json_fields = {
            item
            for item in operation.get("jsonFields") or []
            if isinstance(item, str) and _JSON_OPERATION_FIELD_RE.fullmatch(item)
        }
        if configured_json_fields:
            try:
                body = strict_json_loads(flow.request.raw_content or b"")
            except (TypeError, ValueError):
                body = None
            if isinstance(body, dict):
                for field in configured_json_fields:
                    value = body.get(field)
                    if isinstance(value, str):
                        try:
                            value.encode("utf-8")
                        except UnicodeEncodeError:
                            continue
                        fields[field] = value
                    elif (
                        isinstance(value, int)
                        and not isinstance(value, bool)
                        and -(2**63) <= value <= 2**63 - 1
                    ):
                        fields[field] = str(value)

        body_sha256_field = operation.get("bodySha256Field")
        if (
            isinstance(body_sha256_field, str)
            and body_sha256_field != "operation"
            and _OPERATION_FIELD_RE.fullmatch(body_sha256_field)
            and request_config.get("bodyMode") in {
                "json", "formUrlencoded", BUFFERED_JSON_PASSTHROUGH_REQUEST_MODE
            }
        ):
            raw_body = flow.request.raw_content or b""
            fields[body_sha256_field] = f"sha256:{hashlib.sha256(raw_body).hexdigest()}"
        return fields

    def _allowed_field_paths(self, response_cfg: dict[str, Any]) -> list[tuple[str, ...]]:
        paths = [
            tuple(segment for segment in str(field).split(".") if segment)
            for field in (response_cfg.get("allowedFields") or [])
        ]
        return [path for path in paths if path]

    def _response_projection_error(
        self,
        response_cfg: dict[str, Any],
        mode: str,
        *,
        credential_bearing: bool,
    ) -> PolicyDecision | None:
        fields = response_cfg.get("allowedFields")
        if fields is None or fields == []:
            if credential_bearing:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="credential-bearing response requires a non-empty allowedFields projection",
                    payload={
                        "error": "credential_response_projection_required",
                        "adapter": self.id,
                        "mode": mode,
                    },
                )
            if mode == "json":
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="JSON response projection policy is missing",
                    payload={"error": "response_allowed_fields_missing"},
                )
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="streaming redaction response policy missing allowedFields",
                payload={"error": "streaming_redaction_response_allowed_fields_missing"},
            )
        if (
            not isinstance(fields, list)
            or len(fields) > 64
            or any(
                not isinstance(field, str)
                or len(field) > 256
                or _RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
                for field in fields
            )
            or len(fields) != len(set(fields))
        ):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="response projection policy allowedFields is invalid",
                payload={"error": "response_allowed_fields_invalid", "mode": mode},
            )
        return None

    def _redact_json(self, source: Any, paths: list[tuple[str, ...]]) -> Any:
        if not paths:
            if isinstance(source, list):
                return []
            if isinstance(source, dict):
                return {}
            return None
        if isinstance(source, list):
            return [self._redact_json(item, paths) for item in source]
        if not isinstance(source, dict):
            return None
        grouped: dict[str, list[tuple[str, ...]]] = {}
        for path in paths:
            grouped.setdefault(path[0], []).append(path[1:])
        redacted: dict[str, Any] = {}
        for key, tails in grouped.items():
            if key not in source:
                continue
            if any(not tail for tail in tails):
                redacted[key] = source[key]
                continue
            value = self._redact_json(source[key], [tail for tail in tails if tail])
            if value not in ({}, None):
                redacted[key] = value
        return redacted

    def _redact_json_lines(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        output: list[bytes] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                item = strict_json_loads(line)
            except Exception as exc:
                raise ValueError("json lines body contains invalid JSON") from exc
            redacted = self._redact_json(item, paths)
            output.append(canonical_json(redacted).encode("utf-8"))
        return b"\n".join(output) + (b"\n" if output else b"")

    def _redact_json_array(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        try:
            payload = strict_json_loads(raw)
        except Exception as exc:
            raise ValueError("json array body contains invalid JSON") from exc
        if not isinstance(payload, list):
            raise ValueError("json array body must be a top-level array")
        redacted = [self._redact_json(item, paths) for item in payload]
        return canonical_json(redacted).encode("utf-8")

    def _redact_json_nested(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        try:
            payload = strict_json_loads(raw)
        except Exception as exc:
            raise ValueError("json nested body contains invalid JSON") from exc
        redacted = self._redact_json(payload, paths)
        return canonical_json(redacted).encode("utf-8")

    def _redact_json_sse(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        output: list[bytes] = []
        event_lines: list[bytes] = []
        for raw_line in raw.splitlines():
            line = raw_line.rstrip(b"\r")
            if not line:
                output.extend(self._redact_json_sse_event(event_lines, paths))
                event_lines = []
                continue
            event_lines.append(line)
        if event_lines:
            output.extend(self._redact_json_sse_event(event_lines, paths))
        return b"".join(output)

    def _redact_json_sse_event(self, event_lines: list[bytes], paths: list[tuple[str, ...]]) -> list[bytes]:
        data_parts: list[bytes] = []
        for line in event_lines:
            if line.startswith(b"data:"):
                value = line[5:]
                if value.startswith(b" "):
                    value = value[1:]
                data_parts.append(value)
        if not data_parts:
            return []
        data = b"\n".join(data_parts).strip()
        if data == b"[DONE]":
            return [b"data: [DONE]\n\n"]
        try:
            payload = strict_json_loads(data)
        except Exception as exc:
            raise ValueError("json sse event contains invalid JSON") from exc
        redacted = self._redact_json(payload, paths)
        return [b"data: " + canonical_json(redacted).encode("utf-8") + b"\n\n"]

    def _redact_form_urlencoded(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        allowed = {".".join(path) for path in paths if path}
        pairs = self._parse_form_urlencoded(raw)
        redacted = [
            (key, value)
            for key, value in pairs
            if self._normalized_form_key(key) in allowed
        ]
        return urlencode(redacted, doseq=True).encode("utf-8")

    def _parse_form_urlencoded(self, raw: bytes) -> list[tuple[str, str]]:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("form request is not valid UTF-8") from exc
        if re.search(r"%(?![0-9A-Fa-f]{2})", text):
            raise ValueError("form request contains invalid percent encoding")
        try:
            pairs = parse_qsl(
                text,
                keep_blank_values=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=256,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("form request is invalid") from exc
        if any(not self._normalized_form_key(key) for key, _ in pairs):
            raise ValueError("form request contains an invalid field name")
        return pairs

    def _normalized_form_key(self, key: str) -> str:
        parts = [part for part in re.split(r"\[([^\]]*)\]", key) if part and not part.isdigit()]
        return ".".join(parts)

    def _redact_csv(self, raw: bytes, paths: list[tuple[str, ...]]) -> bytes:
        allowed = {".".join(path) for path in paths if path}
        reader = csv.reader(io.StringIO(raw.decode("utf-8"), newline=""))
        try:
            headers = next(reader)
        except StopIteration as exc:
            raise ValueError("csv body missing header row") from exc
        if not headers:
            raise ValueError("csv body missing header row")
        if len(set(headers)) != len(headers):
            raise ValueError("csv body contains duplicate headers")
        indexes = [index for index, name in enumerate(headers) if name in allowed]
        if not indexes:
            raise ValueError("csv allowedFields did not match the header row")
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow([headers[index] for index in indexes])
        for row in reader:
            if len(row) != len(headers):
                raise ValueError("csv record does not match header width")
            writer.writerow([row[index] for index in indexes])
        return output.getvalue().encode("utf-8")


class GmailV1Adapter(ApiAdapter):
    id = "gmail.v1"

    def _days(self, route: Any) -> int:
        return int(route.adapter_config.get("maxAgeDays", 30))

    def _max_results(self, route: Any) -> int | None:
        value = route.adapter_config.get("maxResults")
        return int(value) if value is not None else None

    def _is_list(self, params: dict[str, str]) -> bool:
        return "message_id" not in params

    def _older_than_days(self, value: str) -> int | None:
        match = OLDER_THAN_RE.search(value or "")
        if not match:
            return None
        count = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "d":
            return count
        if unit == "m":
            return count * 30
        return count * 365

    def _newer_than_days(self, match: re.Match[str]) -> int:
        count = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "d":
            return count
        if unit == "m":
            return count * 30
        return count * 365

    def _append_recent_query(self, query: str, days: int) -> str:
        guard = f"newer_than:{days}d"
        query = query or ""
        if NEWER_THAN_RE.search(query):
            return NEWER_THAN_RE.sub(
                lambda match: match.group(0) if self._newer_than_days(match) <= days else guard,
                query,
            )
        if not query.strip():
            return guard
        return f"({query}) {guard}"

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        profile_decision = self._validate_provider_request_profile(flow, route)
        if not profile_decision.allowed:
            return profile_decision
        denied_equivalents = {
            str(item).strip("/").lower()
            for item in route.adapter_config.get("denyEquivalentEndpoints") or []
        }
        if denied_equivalents:
            path_segments = {
                segment.lower()
                for segment in (
                    validated_request_urlsplit(flow.request.pretty_url).path or ""
                ).split("/")
                if segment
            }
            blocked = sorted(denied_equivalents.intersection(path_segments))
            if blocked:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"gmail equivalent endpoint blocked by policy: {blocked[0]}",
                    payload={"error": "gmail_equivalent_endpoint_blocked", "endpoint": blocked[0]},
                )

        if self._is_list(params):
            response_cfg = route.adapter_config.get("response") or {}
            if (
                response_cfg.get("validateListByMetadataFetch", False)
                and any(
                    self._header_value(flow.request.headers, header) is not None
                    for header in (
                        _GMAIL_PROOF_NONCE_HEADER,
                        _GMAIL_STREAM_PROOF_NONCE_HEADER,
                    )
                )
            ):
                return PolicyDecision(
                    allowed=False,
                    status_code=400,
                    reason="response proof is unsupported for Gmail metadata-fetch lists",
                    payload={"error": "gmail_metadata_fetch_response_proof_unsupported"},
                )
            query = flow.request.query.get("q", "")
            older_than = self._older_than_days(query)
            days = self._days(route)
            if older_than and older_than > days:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"gmail query asks for mail older than {days} days",
                    payload={"error": "gmail_recent_policy", "max_days": days},
                )
            operation = "gmail.messages.list"
        else:
            operation = "gmail.message.get"
        admitted_query = GMAIL_V1_OPERATION_QUERY_KEYS.get(operation)
        if admitted_query is None or not set(flow.request.query).issubset(
            admitted_query
        ):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="Gmail query key is not admitted for the operation",
                payload={"error": "gmail_operation_query_denied"},
            )

        if not self._is_list(params) and route.adapter_config.get(
            "allowMessageGetOnlyFromPriorSearch", True
        ):
            message_id = params["message_id"]
            if not runtime.gmail_message_allowed(self._proof_context(flow, route, params), message_id):
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason="gmail message id was not observed in a validated recent list response for this principal, credential version, policy, user, and cutoff",
                    payload={"error": "gmail_message_age_not_proven", "message_id": message_id},
                )
        return PolicyDecision(allowed=True)

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if self._is_list(params) and route.adapter_config.get("forceQuery", True):
            days = self._days(route)
            flow.request.query["q"] = self._append_recent_query(flow.request.query.get("q", ""), days)
            max_results = self._max_results(route)
            if max_results and int(flow.request.query.get("maxResults", max_results)) > max_results:
                flow.request.query["maxResults"] = str(max_results)
        return PolicyDecision(allowed=True)

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = "gmail.messages.list" if self._is_list(params) else "gmail.message.get"
        fields = {
            "operation": operation,
            "gmailUser": params.get("user", "me"),
        }
        if not self._is_list(params):
            fields["messageId"] = params["message_id"]
        return fields

    def _cutoff_ms(self, route: Any) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._days(route))
        return int(cutoff.timestamp() * 1000)

    def _cache_cutoff_epoch_ms(self, route: Any) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._days(route))
        day_start = datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=timezone.utc)
        return int(day_start.timestamp() * 1000)

    def _proof_context(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, Any]:
        return {
            "route_id": route.id,
            "principal_id": flow.metadata.get("serverware_principal_id"),
            "credential_id": flow.metadata.get("serverware_credential_id") or route.credential_ref,
            "credential_version": flow.metadata.get("serverware_credential_version") or 0,
            "policy_hash": flow.metadata.get("serverware_policy_hash"),
            "gmail_user": params.get("user", "me"),
            "cutoff_epoch_ms": self._cache_cutoff_epoch_ms(route),
        }

    @staticmethod
    def _digest_json(value: Any) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _valid_message_id(value: Any) -> str | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return None
        if len(encoded) > 512 or any(byte < 32 or byte == 127 for byte in encoded):
            return None
        return value

    @staticmethod
    def _decoded_path_param(value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("Gmail path parameter is missing")
        for index, character in enumerate(value):
            if character == "%" and (
                index + 2 >= len(value)
                or re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1 : index + 3]) is None
            ):
                raise ValueError("Gmail path parameter contains invalid percent encoding")
        decoded = unquote(value, encoding="utf-8", errors="strict")
        encoded = decoded.encode("utf-8")
        if not encoded or len(encoded) > 512 or any(byte < 32 or byte == 127 for byte in encoded):
            raise ValueError("Gmail path parameter is invalid")
        return decoded

    def _metadata_fetch_config(self, route: Any) -> dict[str, int] | None:
        response_cfg = route.adapter_config.get("response") or {}
        if not (
            response_cfg.get("validateInternalDate", True)
            and response_cfg.get("validateListByMetadataFetch", False)
        ):
            return None
        config = response_cfg.get("metadataFetch")
        if not isinstance(config, dict):
            raise ValueError("Gmail metadata fetch policy is missing")
        required_fields = {
            "maxMessages",
            "perRequestTimeoutMs",
            "totalTimeoutMs",
            "maxBodyBytes",
        }
        if set(config) != required_fields:
            raise ValueError("Gmail metadata fetch policy fields are invalid")
        bounds = {
            "maxMessages": (1, 32),
            "perRequestTimeoutMs": (1, 3_000),
            "totalTimeoutMs": (1, 10_000),
            "maxBodyBytes": (1, 8_192),
        }
        normalized: dict[str, int] = {}
        for name, (minimum, maximum) in bounds.items():
            value = config.get(name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("Gmail metadata fetch policy is invalid")
            normalized[name] = value
        if normalized["perRequestTimeoutMs"] > normalized["totalTimeoutMs"]:
            raise ValueError("Gmail metadata fetch timeout policy is invalid")
        max_results = route.adapter_config.get("maxResults")
        if (
            type(max_results) is not int
            or max_results < 1
            or normalized["maxMessages"] > max_results
        ):
            raise ValueError("Gmail metadata fetch message limit exceeds maxResults")
        allowed_fields = response_cfg.get("allowedFields")
        if not isinstance(allowed_fields, list) or "id" not in allowed_fields:
            raise ValueError("Gmail metadata fetch response projection must include id")
        return normalized

    def _metadata_origin_and_user(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
    ) -> tuple[str, str]:
        parts = validated_request_urlsplit(flow.request.pretty_url)
        try:
            explicit_port = parts.port
        except ValueError as exc:
            raise ValueError("Gmail parent origin is invalid") from exc
        hostname = (parts.hostname or "").rstrip(".").lower()
        effective_port = explicit_port or (443 if parts.scheme.lower() == "https" else 80)
        if (
            parts.scheme.lower() != "https"
            or parts.username is not None
            or parts.password is not None
            or not hostname
            or parts.scheme.lower() != str(route.scheme).lower()
            or hostname != str(route.host).rstrip(".").lower()
            or effective_port != int(route.port)
        ):
            raise ValueError("Gmail metadata fetch origin does not match the parent route")
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"{rendered_host}:{explicit_port}" if explicit_port is not None else rendered_host
        gmail_user = self._decoded_path_param(params.get("user", "me"))
        return urlunsplit(("https", netloc, "", "", "")), gmail_user

    @staticmethod
    def _internal_date_value(raw_value: Any) -> int | None:
        if isinstance(raw_value, int) and not isinstance(raw_value, bool):
            return raw_value
        if isinstance(raw_value, str) and raw_value and raw_value.isascii():
            try:
                return int(raw_value)
            except ValueError:
                return None
        return None

    def _metadata_audit_event(
        self,
        flow: Any,
        route: Any,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        event = {
            "component": "serverware-python-proxy",
            "principal_id": flow.metadata.get("serverware_principal_id"),
            "route_id": route.id,
            "policy_hash": flow.metadata.get("serverware_policy_hash"),
            "credential_ref": flow.metadata.get("serverware_credential_id"),
            "credential_version": flow.metadata.get("serverware_credential_version"),
            "request_digest": flow.metadata.get("serverware_request_digest"),
            "operation_digest": flow.metadata.get("serverware_operation_digest"),
            "attempt_id": flow.metadata.get("serverware_release_attempt_id"),
            "binding_digest": flow.metadata.get("serverware_release_binding_digest"),
            "flow_id": flow.metadata.get("serverware_release_attempt_id"),
            "grant_id": flow.metadata.get("serverware_release_grant_id"),
            "approval_id": flow.metadata.get("serverware_release_approval_request_id"),
        }
        event.update(details)
        return event

    def _record_metadata_audit(
        self,
        flow: Any,
        route: Any,
        event_type: str,
        details: dict[str, Any],
    ) -> bool:
        parent_binding = self._digest_json(
            {
                "attempt_id": flow.metadata.get("serverware_release_attempt_id"),
                "binding_digest": flow.metadata.get("serverware_release_binding_digest"),
                "operation_digest": flow.metadata.get("serverware_operation_digest"),
                "request_digest": flow.metadata.get("serverware_request_digest"),
                "route_id": route.id,
            }
        )
        phase = event_type.rsplit(".", 1)[-1]
        try:
            db.record_audit_event(
                event_type,
                self._metadata_audit_event(flow, route, details),
                actor_type="data-plane",
                actor_id="serverware-python-proxy",
                idempotency_key=f"gmail-metadata-fanout:{phase}:{parent_binding}",
            )
        except Exception:
            return False
        return True

    def _metadata_child_record(
        self,
        *,
        path: str,
        response_payload: Any | None,
        outcome: str,
    ) -> dict[str, Any]:
        request_digest = self._digest_json(
            {
                "method": "GET",
                "path": path.partition("?")[0],
                "query": [["fields", "id,internalDate"], ["format", "metadata"]],
            }
        )
        response_digest = None
        if response_payload is not None:
            response_digest = self._digest_json(response_payload)
        return {
            "request_digest": request_digest,
            "response_digest": response_digest,
            "outcome": outcome,
        }

    def prepare_response(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
        *,
        authorization_factory: Callable[[], tuple[str, float]] | None = None,
    ) -> PolicyDecision:
        media_type_decision = super().prepare_response(
            flow,
            route,
            params,
            authorization_factory=authorization_factory,
        )
        if not media_type_decision.allowed:
            return media_type_decision
        if not flow.response:
            return PolicyDecision(allowed=True)
        if 200 <= int(flow.response.status_code) < 300:
            media_type_error = self._json_response_media_type_error(flow)
            if media_type_error is not None:
                return media_type_error
        if not self._is_list(params) or not 200 <= int(flow.response.status_code) < 300:
            return PolicyDecision(allowed=True)
        try:
            config = self._metadata_fetch_config(route)
        except ValueError:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="Gmail metadata fetch policy is invalid",
                payload={"error": "gmail_metadata_fetch_config_invalid"},
            )
        if config is None:
            return PolicyDecision(allowed=True)
        response_cfg = route.adapter_config.get("response") or {}
        max_body = response_cfg.get("maxBodyBytes")
        if type(max_body) is not int or len(flow.response.raw_content or b"") > max_body:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": max_body},
            )
        try:
            payload = strict_json_loads(flow.response.raw_content or b"")
        except Exception:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response is not valid JSON",
                payload={"error": "gmail_response_invalid_json"},
            )
        if not isinstance(payload, dict):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response must be a JSON object",
                payload={"error": "gmail_response_invalid_json"},
            )
        messages = payload.get("messages")
        if messages is None:
            return PolicyDecision(allowed=True)
        if not isinstance(messages, list):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail metadata-fetch messages field is invalid",
                payload={"error": "gmail_metadata_fetch_messages_invalid"},
            )
        if len(messages) > config["maxMessages"]:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail metadata-fetch message limit exceeded",
                payload={
                    "error": "gmail_metadata_fetch_message_limit_exceeded",
                    "max_messages": config["maxMessages"],
                },
            )

        cutoff_ms = self._cutoff_ms(route)
        seen: set[str] = set()
        planned = 0
        for item in messages:
            if not isinstance(item, dict):
                continue
            message_id = self._valid_message_id(item.get("id"))
            if message_id is None:
                continue
            if message_id in seen:
                return PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason="gmail metadata-fetch response contains a duplicate id",
                    payload={"error": "gmail_metadata_fetch_duplicate_id"},
                )
            seen.add(message_id)
            if "internalDate" in item:
                value = self._internal_date_value(item.get("internalDate"))
                if value is None:
                    return PolicyDecision(
                        allowed=False,
                        status_code=502,
                        reason="gmail response internalDate is not an epoch-ms integer",
                        payload={"error": "gmail_response_invalid_internal_date"},
                    )
                if value < cutoff_ms:
                    return PolicyDecision(
                        allowed=False,
                        status_code=502,
                        reason=f"gmail response contains mail older than {self._days(route)} days",
                        payload={"error": "gmail_response_too_old", "max_days": self._days(route)},
                    )
            else:
                planned += 1
        if planned == 0:
            return PolicyDecision(allowed=True)
        return PolicyDecision(
            allowed=False,
            status_code=503,
            reason=(
                "Gmail list metadata hydration is disabled because each hidden "
                "credential-bearing child request lacks an explicit bounded "
                "reservation, claim, and audit lifecycle"
            ),
            payload={
                "error": "gmail_metadata_hydration_accounting_unavailable",
                "plannedChildren": planned,
            },
        )
        if authorization_factory is None:
            return PolicyDecision(
                allowed=False,
                status_code=503,
                reason="gmail metadata-fetch credential context is missing",
                payload={"error": "gmail_metadata_fetch_credential_context_missing"},
            )
        try:
            origin, gmail_user = self._metadata_origin_and_user(flow, route, params)
        except (UnicodeError, ValueError):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail metadata-fetch origin is invalid",
                payload={"error": "gmail_metadata_fetch_origin_invalid"},
            )
        config_digest = self._digest_json(
            {
                "max_messages": config["maxMessages"],
                "per_request_timeout_ms": config["perRequestTimeoutMs"],
                "total_timeout_ms": config["totalTimeoutMs"],
                "max_body_bytes": config["maxBodyBytes"],
            }
        )
        try:
            deadline = http_client.HttpDeadline.after(config["totalTimeoutMs"] / 1000)
        except http_client.HttpClientError:
            return PolicyDecision(
                allowed=False,
                status_code=500,
                reason="gmail metadata-fetch deadline policy is invalid",
                payload={"error": "gmail_metadata_fetch_config_invalid"},
            )
        if not self._record_metadata_audit(
            flow,
            route,
            "data_plane.gmail.metadata_fanout.started",
            {
                "outcome": "started",
                "planned_count": planned,
                "cutoff_epoch_ms": cutoff_ms,
                "metadata_fetch_config_digest": config_digest,
            },
        ):
            return PolicyDecision(
                allowed=False,
                status_code=503,
                reason="gmail metadata-fetch start audit is unavailable",
                payload={"error": "gmail_metadata_fetch_start_audit_unavailable"},
            )

        released: list[dict[str, Any]] = []
        child_records: list[dict[str, Any]] = []
        outcomes: Counter[str] = Counter()
        blocked_decision: PolicyDecision | None = None
        encoded_user = quote(gmail_user, safe="")
        for item in messages:
            if not isinstance(item, dict):
                continue
            message_id = self._valid_message_id(item.get("id"))
            if message_id is None:
                continue
            if "internalDate" in item:
                released.append(item)
                continue
            path = (
                f"/gmail/v1/users/{encoded_user}/messages/{quote(message_id, safe='')}"
                "?format=metadata&fields=id%2CinternalDate"
            )
            dispatch_deadline: float | None = None
            dispatch_expires_at_epoch_ms = flow.metadata.get(
                "serverware_release_dispatch_expires_at_epoch_ms"
            )
            dispatch_deadline_required = (
                flow.metadata.get("serverware_release_state") == "dispatching"
            )
            if dispatch_expires_at_epoch_ms is not None or dispatch_deadline_required:
                if (
                    type(dispatch_expires_at_epoch_ms) is not int
                    or dispatch_expires_at_epoch_ms < 0
                ):
                    dispatch_remaining = 0.0
                else:
                    dispatch_remaining = (
                        dispatch_expires_at_epoch_ms - int(time.time() * 1000)
                    ) / 1000
                if dispatch_remaining < _MIN_GMAIL_CHILD_AUTHORITY_SECONDS:
                    child_records.append(
                        self._metadata_child_record(
                            path=path,
                            response_payload=None,
                            outcome="blocked_release_authority",
                        )
                    )
                    outcomes["blocked"] += 1
                    blocked_decision = PolicyDecision(
                        allowed=False,
                        status_code=503,
                        reason="gmail metadata-fetch release authority expired",
                        payload={"error": "gmail_metadata_fetch_release_authority_expired"},
                    )
                    break
                dispatch_deadline = time.monotonic() + dispatch_remaining
            try:
                authorization, credential_lease_deadline = authorization_factory()
            except Exception:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=None,
                        outcome="blocked_credential",
                    )
                )
                outcomes["blocked"] += 1
                blocked_decision = PolicyDecision(
                    allowed=False,
                    status_code=503,
                    reason="gmail metadata-fetch credential authority changed",
                    payload={"error": "gmail_metadata_fetch_credential_authority_changed"},
                )
                break
            now_monotonic = time.monotonic()
            child_deadline_at = min(
                deadline.expires_at,
                credential_lease_deadline,
                dispatch_deadline if dispatch_deadline is not None else float("inf"),
            )
            child_timeout_seconds = min(
                config["perRequestTimeoutMs"] / 1000,
                child_deadline_at - now_monotonic,
            )
            if child_timeout_seconds <= 0:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=None,
                        outcome="gmail_metadata_fetch_total_deadline_exhausted",
                    )
                )
                outcomes["dropped"] += 1
                continue
            child_deadline = http_client.HttpDeadline(child_deadline_at)
            metadata: Any | None = None
            try:
                metadata = _secure_bounded_metadata_get(
                    origin=origin,
                    path=path,
                    headers={"Authorization": authorization},
                    timeout_seconds=child_timeout_seconds,
                    max_body_bytes=config["maxBodyBytes"],
                    deadline=child_deadline,
                )
            except http_client.HttpClientError:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=None,
                        outcome="dropped_transport_or_response",
                    )
                )
                outcomes["dropped"] += 1
                continue
            token = authorization.removeprefix("Bearer ")
            try:
                serialized_metadata = json.dumps(
                    metadata,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            except (TypeError, ValueError):
                serialized_metadata = ""
            if authorization in serialized_metadata or token in serialized_metadata:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=metadata,
                        outcome="dropped_credential_reflection",
                    )
                )
                outcomes["dropped"] += 1
                continue
            if not isinstance(metadata, dict) or metadata.get("id") != message_id:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=metadata,
                        outcome="dropped_json_or_id",
                    )
                )
                outcomes["dropped"] += 1
                continue
            internal_date = metadata.get("internalDate")
            if (
                not isinstance(internal_date, str)
                or not internal_date
                or not internal_date.isascii()
                or not internal_date.isdigit()
            ):
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=metadata,
                        outcome="dropped_internal_date_invalid",
                    )
                )
                outcomes["dropped"] += 1
                continue
            if int(internal_date) < cutoff_ms:
                child_records.append(
                    self._metadata_child_record(
                        path=path,
                        response_payload=metadata,
                        outcome="blocked_too_old",
                    )
                )
                outcomes["blocked"] += 1
                blocked_decision = PolicyDecision(
                    allowed=False,
                    status_code=502,
                    reason=f"gmail response contains mail older than {self._days(route)} days",
                    payload={"error": "gmail_response_too_old", "max_days": self._days(route)},
                )
                break
            merged = dict(item)
            merged["id"] = metadata["id"]
            merged["internalDate"] = internal_date
            released.append(merged)
            child_records.append(
                self._metadata_child_record(
                    path=path,
                    response_payload=metadata,
                    outcome="hydrated",
                )
            )
            outcomes["hydrated"] += 1

        completion_details = {
            "outcome": "blocked" if blocked_decision is not None else "completed",
            "planned_count": planned,
            "attempted_count": len(child_records),
            "hydrated_count": outcomes["hydrated"],
            "dropped_count": outcomes["dropped"],
            "blocked_count": outcomes["blocked"],
            "ordered_child_digest": self._digest_json(child_records),
            "metadata_fetch_config_digest": config_digest,
        }
        if not self._record_metadata_audit(
            flow,
            route,
            "data_plane.gmail.metadata_fanout.completed",
            completion_details,
        ):
            return PolicyDecision(
                allowed=False,
                status_code=503,
                reason="gmail metadata-fetch completion audit is unavailable",
                payload={"error": "gmail_metadata_fetch_completion_audit_unavailable"},
            )
        if blocked_decision is not None:
            return blocked_decision
        payload["messages"] = released
        flow.response.set_text(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        return PolicyDecision(allowed=True)

    def _validate_internal_date(self, route: Any, item: dict[str, Any]) -> PolicyDecision:
        raw_value = item.get("internalDate")
        if raw_value is None:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response missing internalDate required by policy",
                payload={"error": "gmail_response_missing_internal_date"},
            )
        value = self._internal_date_value(raw_value)
        if value is None:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response internalDate is not an epoch-ms integer",
                payload={"error": "gmail_response_invalid_internal_date"},
            )
        if value < self._cutoff_ms(route):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason=f"gmail response contains mail older than {self._days(route)} days",
                payload={"error": "gmail_response_too_old", "max_days": self._days(route)},
            )
        if value > int(time.time() * 1000) + _GMAIL_INTERNAL_DATE_FUTURE_SKEW_MS:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason=(
                    "gmail response internalDate is materially in the future"
                ),
                payload={
                    "error": "gmail_response_internal_date_in_future",
                    "maxFutureSkewSeconds": (
                        _GMAIL_INTERNAL_DATE_FUTURE_SKEW_MS // 1000
                    ),
                },
            )
        return PolicyDecision(allowed=True)

    def validate_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        flow.metadata.pop("serverware_gmail_pending_proofs", None)
        if not flow.response:
            return PolicyDecision(allowed=True)
        if not 200 <= int(flow.response.status_code) < 300:
            return super().validate_response(flow, route, params)
        response_cfg = route.adapter_config.get("response") or {}
        media_type_error = self._json_response_media_type_error(flow)
        if media_type_error is not None:
            return media_type_error
        projection_error = self._response_projection_error(
            response_cfg,
            "json",
            credential_bearing=bool(getattr(route, "credential_ref", None)),
        )
        if projection_error is not None:
            return projection_error
        max_body = response_cfg.get("maxBodyBytes")
        if max_body is None or len(flow.response.raw_content or b"") > int(max_body):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response body exceeded policy limit",
                payload={"error": "response_body_too_large", "maxBodyBytes": max_body},
            )
        validate_internal_date = response_cfg.get("validateInternalDate", True)
        try:
            payload = strict_json_loads(flow.response.raw_content or b"")
        except Exception:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response is not valid JSON",
                payload={"error": "gmail_response_invalid_json"},
            )
        if not isinstance(payload, dict):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail response must be a JSON object",
                payload={"error": "gmail_response_invalid_json"},
            )

        if self._is_list(params):
            if validate_internal_date:
                messages = payload.get("messages") or []
                if not isinstance(messages, list):
                    return PolicyDecision(
                        allowed=False,
                        status_code=502,
                        reason="gmail response messages field is invalid",
                        payload={"error": "gmail_response_messages_invalid"},
                    )
                pending_proofs: dict[str, int] = {}
                validated_messages: list[dict[str, Any]] = []
                seen: set[str] = set()
                for item in messages:
                    if not isinstance(item, dict):
                        continue
                    message_id = self._valid_message_id(item.get("id"))
                    if message_id is None:
                        continue
                    if message_id in seen:
                        return PolicyDecision(
                            allowed=False,
                            status_code=502,
                            reason="gmail response contains a duplicate id",
                            payload={"error": "gmail_metadata_fetch_duplicate_id"},
                        )
                    seen.add(message_id)
                    if item.get("internalDate") is None and response_cfg.get("validateListByMetadataFetch", False):
                        continue
                    decision = self._validate_internal_date(route, item)
                    if not decision.allowed:
                        return decision
                    internal_date = self._internal_date_value(item.get("internalDate"))
                    if internal_date is None:
                        return PolicyDecision(
                            allowed=False,
                            status_code=502,
                            reason="gmail response internalDate is not an epoch-ms integer",
                            payload={"error": "gmail_response_invalid_internal_date"},
                        )
                    item["serverwareAgeProof"] = "validated"
                    pending_proofs[message_id] = internal_date + self._days(route) * 86_400_000
                    validated_messages.append(item)
                payload["messages"] = validated_messages
                flow.metadata["serverware_gmail_pending_proofs"] = pending_proofs
            self._apply_allowed_fields(flow, route, payload)
            self._normalize_response_headers(flow, response_cfg, "json")
            return PolicyDecision(allowed=True)

        decision = PolicyDecision(allowed=True)
        requested_message_id = self._valid_message_id(params.get("message_id"))
        response_message_id = self._valid_message_id(payload.get("id"))
        if (
            requested_message_id is None
            or response_message_id is None
            or response_message_id != requested_message_id
        ):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="gmail detail response id does not match the requested message id",
                payload={
                    "error": "gmail_response_message_id_mismatch",
                    "requestedMessageId": requested_message_id,
                },
            )
        if validate_internal_date:
            decision = self._validate_internal_date(route, payload)
            if decision.allowed and payload.get("id"):
                message_id = self._valid_message_id(payload.get("id"))
                if message_id is not None:
                    internal_date = self._internal_date_value(payload.get("internalDate"))
                    if internal_date is not None:
                        flow.metadata["serverware_gmail_pending_proofs"] = {
                            message_id: internal_date + self._days(route) * 86_400_000
                        }
        self._apply_allowed_fields(flow, route, payload)
        if decision.allowed:
            self._normalize_response_headers(flow, response_cfg, "json")
        return decision

    def finalize_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        pending = flow.metadata.pop("serverware_gmail_pending_proofs", None)
        if not isinstance(pending, dict) or not pending:
            return PolicyDecision(allowed=True)
        try:
            payload = strict_json_loads(flow.response.raw_content or b"")
        except Exception:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="projected gmail response is not valid JSON",
                payload={"error": "gmail_response_projection_invalid"},
            )
        pending_set = set(pending)
        emitted: list[str] = []
        if self._is_list(params):
            messages = payload.get("messages") if isinstance(payload, dict) else None
            if isinstance(messages, list):
                for item in messages:
                    if not isinstance(item, dict) or item.get("serverwareAgeProof") != "validated":
                        continue
                    message_id = self._valid_message_id(item.get("id"))
                    if message_id in pending_set:
                        emitted.append(message_id)
        elif isinstance(payload, dict):
            message_id = self._valid_message_id(payload.get("id"))
            if message_id in pending_set:
                emitted.append(message_id)
        if not emitted:
            return PolicyDecision(allowed=True)
        try:
            runtime.cache_gmail_message_ids(
                self._proof_context(flow, route, params),
                emitted,
                ttl_seconds=int(route.adapter_config.get("cacheTtlSeconds", 1800)),
                max_age_expires_at_epoch_ms={
                    message_id: pending[message_id] for message_id in emitted
                },
            )
        except Exception:
            return PolicyDecision(
                allowed=False,
                status_code=503,
                reason="gmail direct-read proof commit failed",
                payload={"error": "gmail_direct_read_proof_commit_failed"},
            )
        return PolicyDecision(allowed=True)

    def _apply_allowed_fields(self, flow: Any, route: Any, payload: dict[str, Any]) -> None:
        response_cfg = route.adapter_config.get("response") or {}
        allowed_fields = [
            tuple(segment for segment in str(field).split(".") if segment)
            for field in (response_cfg.get("allowedFields") or [])
        ]
        allowed_fields = [field for field in allowed_fields if field]
        if not allowed_fields:
            flow.response.set_text("{}")
            return

        def copy_path(source: dict[str, Any], target: dict[str, Any], path: tuple[str, ...]) -> None:
            if not path:
                return
            key = path[0]
            if key not in source:
                return
            if len(path) == 1:
                target[key] = source[key]
                return
            child = source.get(key)
            if isinstance(child, dict):
                nested = target.setdefault(key, {})
                if isinstance(nested, dict):
                    copy_path(child, nested, path[1:])

        def filter_message(item: dict[str, Any], *, include_age_proof: bool = False) -> dict[str, Any]:
            filtered: dict[str, Any] = {}
            for path in allowed_fields:
                copy_path(item, filtered, path)
            payload_value = filtered.get("payload")
            if isinstance(payload_value, dict) and isinstance(payload_value.get("headers"), list):
                allowed_header_names = {
                    str(name).casefold()
                    for name in (response_cfg.get("allowedMessageHeaderNames") or [])
                }
                payload_value["headers"] = [
                    {"name": str(header["name"]), "value": str(header.get("value", ""))}
                    for header in payload_value["headers"]
                    if isinstance(header, dict)
                    and isinstance(header.get("name"), str)
                    and header["name"].casefold() in allowed_header_names
                ]
            if include_age_proof and item.get("serverwareAgeProof") == "validated":
                filtered["serverwareAgeProof"] = item["serverwareAgeProof"]
            return filtered

        if "messages" in payload and isinstance(payload["messages"], list):
            filtered_payload: dict[str, Any] = {
                "messages": [
                    filter_message(item, include_age_proof=True) if isinstance(item, dict) else item
                    for item in payload["messages"]
                ]
            }
            flow.response.set_text(canonical_json(filtered_payload))
            return

        filtered = filter_message(payload)
        flow.response.set_text(canonical_json(filtered))


X_V2_READ_OPERATION_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "accountActivity.read",
        (
            "/2/account_activity/subscriptions/count",
            "/2/account_activity/webhooks/{webhook_id}/subscriptions/all",
            "/2/account_activity/webhooks/{webhook_id}/subscriptions/all/list",
        ),
    ),
    ("activity.read", ("/2/activity/subscriptions",)),
    ("analytics.read", ("/2/media/analytics", "/2/tweets/analytics")),
    (
        "bookmarks.read",
        (
            "/2/users/{id}/bookmarks",
            "/2/users/{id}/bookmarks/folders",
            "/2/users/{id}/bookmarks/folders/{folder_id}",
        ),
    ),
    (
        "chat.read",
        (
            "/2/chat/conversations",
            "/2/chat/conversations/{id}",
            "/2/chat/conversations/{id}/events",
            "/2/chat/media/{id}/{media_hash_key}",
        ),
    ),
    ("communities.read", ("/2/communities/search", "/2/communities/{id}")),
    ("compliance.read", ("/2/compliance/jobs", "/2/compliance/jobs/{id}")),
    ("connections.read", ("/2/connections",)),
    (
        "directMessages.read",
        (
            "/2/dm_conversations/media/{dm_id}/{media_id}/{resource_id}",
            "/2/dm_conversations/with/{participant_id}/dm_events",
            "/2/dm_conversations/{id}/dm_events",
            "/2/dm_events",
            "/2/dm_events/{event_id}",
        ),
    ),
    ("insights.read", ("/2/insights/28hr", "/2/insights/historical")),
    (
        "lists.read",
        (
            "/2/lists/{id}",
            "/2/lists/{id}/followers",
            "/2/lists/{id}/members",
            "/2/lists/{id}/tweets",
            "/2/users/{id}/followed_lists",
            "/2/users/{id}/list_memberships",
            "/2/users/{id}/owned_lists",
            "/2/users/{id}/pinned_lists",
        ),
    ),
    (
        "media.read",
        (
            "/2/media",
            "/2/media/upload",
            "/2/media/{media_key}",
        ),
    ),
    ("news.read", ("/2/news/search", "/2/news/{id}")),
    (
        "notes.read",
        (
            "/2/notes/search/notes_written",
            "/2/notes/search/posts_eligible_for_notes",
        ),
    ),
    ("schema.read", ("/2/openapi.json",)),
    (
        "search.read",
        (
            "/2/tweets/counts/all",
            "/2/tweets/counts/recent",
            "/2/tweets/search/all",
            "/2/tweets/search/recent",
        ),
    ),
    (
        "spaces.read",
        (
            "/2/spaces",
            "/2/spaces/by/creator_ids",
            "/2/spaces/search",
            "/2/spaces/{id}",
            "/2/spaces/{id}/buyers",
            "/2/spaces/{id}/tweets",
        ),
    ),
    (
        "trends.read",
        (
            "/2/trends/by/woeid/{woeid}",
            "/2/users/personalized_trends",
        ),
    ),
    (
        "tweets.read",
        (
            "/2/tweets",
            "/2/tweets/{id}",
            "/2/tweets/{id}/liking_users",
            "/2/tweets/{id}/quote_tweets",
            "/2/tweets/{id}/retweeted_by",
            "/2/tweets/{id}/retweets",
            "/2/users/reposts_of_me",
            "/2/users/{id}/liked_tweets",
            "/2/users/{id}/mentions",
            "/2/users/{id}/timelines/reverse_chronological",
            "/2/users/{id}/tweets",
        ),
    ),
    ("usage.read", ("/2/usage/tweets",)),
    (
        "users.read",
        (
            "/2/users",
            "/2/users/by",
            "/2/users/by/username/{username}",
            "/2/users/me",
            "/2/users/public_keys",
            "/2/users/search",
            "/2/users/{id}",
            "/2/users/{id}/affiliates",
            "/2/users/{id}/blocking",
            "/2/users/{id}/followers",
            "/2/users/{id}/following",
            "/2/users/{id}/muting",
            "/2/users/{id}/public_keys",
        ),
    ),
    (
        "webhooks.read",
        (
            "/2/tweets/search/webhooks",
            "/2/webhooks",
        ),
    ),
)

X_V2_READ_OPERATIONS = frozenset(operation for operation, _ in X_V2_READ_OPERATION_PATHS)


def _x_path_template_matches(path: str, template: str) -> bool:
    path_segments = path.strip("/").split("/")
    template_segments = template.strip("/").split("/")
    if len(path_segments) != len(template_segments):
        return False
    return all(
        bool(path_segment)
        and (template_segment == path_segment or template_segment.startswith("{") and template_segment.endswith("}"))
        for path_segment, template_segment in zip(path_segments, template_segments, strict=True)
    )


def _x_read_operation(path: str) -> str | None:
    matches: list[tuple[int, str]] = []
    for operation, templates in X_V2_READ_OPERATION_PATHS:
        for template in templates:
            if _x_path_template_matches(path, template):
                specificity = sum(
                    not (segment.startswith("{") and segment.endswith("}"))
                    for segment in template.strip("/").split("/")
                )
                matches.append((specificity, operation))
    if not matches:
        return None
    matches.sort(reverse=True)
    if len(matches) > 1 and matches[0][0] == matches[1][0] and matches[0][1] != matches[1][1]:
        return None
    return matches[0][1]


class XV2Adapter(ApiAdapter):
    id = "x.v2"

    def validate_credential_metadata(
        self,
        route: Any,
        metadata: dict[str, Any] | None,
    ) -> PolicyDecision:
        allowed_app_ids = set(route.adapter_config.get("appIds") or [])
        if not allowed_app_ids:
            return PolicyDecision(allowed=True)
        metadata = metadata or {}
        app_ids = {
            value
            for name in ("x_app_id", "app_id")
            if isinstance((value := metadata.get(name)), str) and value
        }
        if len(app_ids) != 1:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 credential app aliases are missing or contradictory",
                payload={"error": "x_app_id_ambiguous"},
            )
        credential_app_id = next(iter(app_ids))
        if credential_app_id not in allowed_app_ids:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 credential app id is not allowed by route policy",
                payload={"error": "x_app_id_denied"},
            )
        return PolicyDecision(allowed=True)

    def validate_credential(self, route: Any, credential: dict[str, Any] | None) -> PolicyDecision:
        metadata = (credential or {}).get("metadata")
        return self.validate_credential_metadata(
            route,
            metadata if isinstance(metadata, dict) else None,
        )

    def _operation(self, flow: Any) -> str | None:
        path = (
            validated_request_urlsplit(flow.request.pretty_url).path or "/"
        ).rstrip("/") or "/"
        method = flow.request.method.upper()
        if method == "POST" and path == "/2/tweets":
            return "tweets.write"
        return _x_read_operation(path) if method == "GET" else None

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        operation = self._operation(flow)
        if operation is None:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 unknown provider operation blocked by policy",
                payload={"error": "x_unknown_operation_blocked"},
            )
        if route.adapter_config.get("blockWrites", True) and not operation.endswith(".read"):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 write operation blocked by read-only policy",
                payload={"error": "x_write_blocked", "mode": route.adapter_config.get("mode", "readOnly")},
            )
        profile_decision = self._validate_provider_request_profile(flow, route)
        if not profile_decision.allowed:
            return profile_decision
        path = (
            validated_request_urlsplit(flow.request.pretty_url).path or "/"
        ).rstrip("/") or "/"
        if (
            route.adapter_config.get("mode") == "recentSearchOnly"
            and path not in X_V2_RECENT_SEARCH_PATHS
        ):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="x.v2 endpoint is outside the recent-search surface",
                payload={"error": "x_recent_search_endpoint_denied", "path": path},
            )
        allowed_reads = set(route.adapter_config.get("allowedReadOperations") or [])
        if operation.endswith(".read") and operation not in allowed_reads:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"x.v2 read operation {operation} is not allowed by route policy",
                payload={"error": "x_read_operation_not_allowed", "operation": operation},
            )
        return PolicyDecision(allowed=True)

    def rewrite_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if self._operation(flow) == "search.read" and any(
            constraint.get("type") == "responseDateWindow" for constraint in route.constraints
        ):
            fields = {
                item.strip()
                for item in str(flow.request.query.get("tweet.fields") or "").split(",")
                if item.strip()
            }
            fields.add("created_at")
            flow.request.query["tweet.fields"] = ",".join(sorted(fields))
        return PolicyDecision(allowed=True)

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        operation = self._operation(flow)
        fields = {"operation": operation or ""}
        path = (
            validated_request_urlsplit(flow.request.pretty_url).path or "/"
        ).rstrip("/") or "/"
        identifier = params.get("id")
        if isinstance(identifier, str):
            if path.startswith("/2/tweets/"):
                fields["tweetId"] = identifier
            elif path.startswith("/2/users/"):
                fields["userId"] = identifier
            elif path.startswith("/2/lists/"):
                fields["listId"] = identifier
            elif path.startswith("/2/spaces/"):
                fields["spaceId"] = identifier
        for param_name, field_name in (
            ("username", "username"),
            ("tweet_id", "tweetId"),
            ("user_id", "userId"),
            ("list_id", "listId"),
            ("space_id", "spaceId"),
        ):
            value = params.get(param_name)
            if isinstance(value, str):
                fields[field_name] = value
        catalog = adapter_operation_field_names(
            self.id, str(fields["operation"])
        )
        if catalog is None or not set(fields).issubset(catalog):
            raise ValueError("x.v2 emitted an unknown operation field")
        return fields


class NpmRegistryAdapter(ApiAdapter):
    id = "npm.registry"

    def _is_public_registry_publish(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
    ) -> bool:
        if getattr(route, "host", None) != NPM_PUBLIC_REGISTRY_HOST:
            return False
        operation = (flow.metadata.get("serverware_operation") or {}).get("operation")
        if isinstance(operation, str):
            return operation == "npm.publish"
        try:
            body = (
                self._json_body(flow)
                if flow.request.method.upper() not in {"GET", "HEAD"}
                else None
            )
            return self._operation_name(flow, params, body) == "publish"
        except (UnicodeError, ValueError, RecursionError):
            return False

    @staticmethod
    def _public_registry_receipt_policy_error(route: Any) -> PolicyDecision | None:
        response = route.adapter_config.get("response") or {}
        has_public_response_constraint = any(
            isinstance(constraint, dict)
            and constraint.get("type") in {"responseBinding", "responseJson"}
            and (
                constraint.get("operations") is None
                or "npm.publish" in constraint.get("operations", [])
            )
            for constraint in (getattr(route, "constraints", ()) or ())
        )
        if (
            route.adapter_config.get("publishResponseContract")
            != NPM_PUBLIC_REGISTRY_RECEIPT_CONTRACT
            or response.get("mode") != "json"
            or response.get("allowedFields") != list(NPM_PUBLIC_REGISTRY_RECEIPT_FIELDS)
            or response.get("allowedHeaders") != []
            or has_public_response_constraint
        ):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt policy is invalid",
                payload={"error": "npm_public_publish_receipt_policy_invalid"},
            )
        return None

    def _public_registry_receipt_error(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
        *,
        validate_body: bool,
    ) -> PolicyDecision | None:
        if not self._is_public_registry_publish(flow, route, params):
            return None
        policy_error = self._public_registry_receipt_policy_error(route)
        if policy_error is not None:
            return policy_error
        status_code = int(flow.response.status_code)
        if 200 <= status_code < 300 and status_code not in {200, 201}:
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt status is not allowed",
                payload={
                    "error": "npm_public_publish_receipt_status_denied",
                    "upstreamStatus": status_code,
                },
            )
        if not validate_body or status_code not in {200, 201}:
            return None
        response = route.adapter_config.get("response") or {}
        max_body_bytes = response.get("maxBodyBytes")
        if (
            not isinstance(max_body_bytes, int)
            or isinstance(max_body_bytes, bool)
            or not 1 <= max_body_bytes <= 65536
            or len(flow.response.raw_content or b"") > max_body_bytes
        ):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt exceeded its body limit",
                payload={"error": "npm_public_publish_receipt_body_denied"},
            )
        try:
            payload = strict_json_loads(flow.response.raw_content or b"")
        except (UnicodeError, ValueError, RecursionError):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt is not strict JSON",
                payload={"error": "npm_public_publish_receipt_invalid_json"},
            )
        if not isinstance(payload, dict):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt must be a JSON object",
                payload={"error": "npm_public_publish_receipt_object_required"},
            )
        if any(field in payload and payload[field] is not True for field in NPM_PUBLIC_REGISTRY_RECEIPT_FIELDS):
            return PolicyDecision(
                allowed=False,
                status_code=502,
                reason="public npm publish receipt contains a contradictory success flag",
                payload={"error": "npm_public_publish_receipt_success_denied"},
            )
        return None

    def prepare_response(
        self,
        flow: Any,
        route: Any,
        params: dict[str, str],
        *,
        authorization_factory: Callable[[], tuple[str, float]] | None = None,
    ) -> PolicyDecision:
        decision = super().prepare_response(
            flow,
            route,
            params,
            authorization_factory=authorization_factory,
        )
        if not decision.allowed or not flow.response:
            return decision
        return self._public_registry_receipt_error(
            flow,
            route,
            params,
            validate_body=False,
        ) or PolicyDecision(allowed=True)

    def validate_response(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        if flow.response and self._is_public_registry_publish(flow, route, params):
            response_cfg, profile_error = self._response_profile(flow, route)
            if profile_error is not None:
                return profile_error
            assert response_cfg is not None
            if response_cfg.get("mode") == "json":
                media_type_error = self._json_response_media_type_error(flow)
                if media_type_error is not None:
                    return media_type_error
            receipt_error = self._public_registry_receipt_error(
                flow,
                route,
                params,
                validate_body=True,
            )
            if receipt_error is not None:
                return receipt_error
        return super().validate_response(flow, route, params)

    def _registry_path(self, flow: Any) -> str:
        path = validated_request_urlsplit(flow.request.pretty_url).path or "/"
        if path.startswith("/npm/"):
            return path[4:] or "/"
        if path == "/npm":
            return "/"
        return path

    @staticmethod
    def _json_body(flow: Any) -> Any:
        raw = flow.request.raw_content or b""
        if not raw:
            return None
        return strict_json_loads(raw)

    @staticmethod
    def _valid_package_name(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        if value.startswith("@"):
            if value.count("/") != 1:
                return False
            scope, package = value.split("/", 1)
            return bool(
                len(scope) - 1 <= 214
                and len(package) <= 214
                and re.fullmatch(r"@[A-Za-z0-9._~-]+", scope)
                and re.fullmatch(r"[A-Za-z0-9@._~-]+", package)
            )
        return bool(
            "/" not in value
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._~-]{0,213}", value)
        )

    @staticmethod
    def _valid_dist_tag_version(value: Any) -> bool:
        return bool(
            isinstance(value, str)
            and len(value.encode("utf-8")) <= 256
            and re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+~-]{0,255}", value)
        )

    @staticmethod
    def _has_publish_attachment_payload(body: dict[str, Any]) -> bool:
        if "tarball_integrity" in body:
            return True
        attachments = body.get("_attachments")
        if attachments is None:
            return False
        if not isinstance(attachments, dict):
            return True
        return any(
            not isinstance(attachment, dict) or "data" in attachment
            for attachment in attachments.values()
        )

    def _operation_name(
        self,
        flow: Any,
        params: dict[str, str],
        body: Any = None,
    ) -> str:
        method = flow.request.method.upper()
        path = self._registry_path(flow)
        if path != "/" and path.endswith("/"):
            raise ValueError("npm operation path must not have a trailing slash")
        segments = path.strip("/").split("/") if path != "/" else []

        def package_segment(value: str) -> bool:
            if "%2f" in value:
                if value.count("%2f") != 1:
                    return False
                scope, package = value.split("%2f", 1)
                return bool(
                    len(scope) - 1 <= 214
                    and len(package) <= 214
                    and re.fullmatch(r"@[A-Za-z0-9._~-]+", scope)
                    and re.fullmatch(r"[A-Za-z0-9@._~-]+", package)
                )
            return bool(
                not value.startswith("@")
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._~-]{0,213}", value)
            )

        if method == "POST" and segments == ["-", "npm", "v1", "tokens"]:
            return "tokenCreate"
        if (
            method == "DELETE"
            and len(segments) == 6
            and segments[:5] == ["-", "npm", "v1", "tokens", "token"]
            and bool(segments[5])
        ):
            return "tokenWrite"
        if (
            method in {"PUT", "DELETE"}
            and len(segments) == 5
            and segments[:2] == ["-", "package"]
            and package_segment(segments[2])
            and segments[3] == "dist-tags"
            and bool(segments[4])
        ):
            return "distTagWrite"
        if (
            method in {"PUT", "DELETE"}
            and len(segments) == 3
            and package_segment(segments[0])
            and segments[1] == "-rev"
            and bool(segments[2])
        ) or (
            method == "DELETE"
            and len(segments) == 5
            and package_segment(segments[0])
            and segments[1] == "-"
            and bool(segments[2])
            and segments[3] == "-rev"
            and bool(segments[4])
        ):
            return "unpublish"
        if (
            method == "POST"
            and len(segments) == 4
            and segments[:2] == ["-", "package"]
            and package_segment(segments[2])
            and segments[3] == "access"
        ) or (
            method == "POST"
            and segments == ["-", "npm", "v1", "user"]
        ) or (
            method in {"PUT", "DELETE"}
            and len(segments) == 5
            and segments[:2] == ["-", "team"]
            and all(segments[index] for index in (2, 3))
            and segments[4] == "package"
        ):
            return "metadataWrite"
        if (
            method == "PUT"
            and len(segments) == 1
            and package_segment(segments[0])
            and isinstance(body, dict)
        ):
            if self._has_publish_attachment_payload(body):
                return "publish"
            return "metadataWrite" if "_rev" in body else "publish"
        raise ValueError("npm operation does not match the closed write grammar")

    def operation_fields(self, flow: Any, route: Any, params: dict[str, str]) -> dict[str, str]:
        method = flow.request.method.upper()
        body = self._json_body(flow) if method not in {"GET", "HEAD"} else None
        operation = self._operation_name(flow, params, body)
        self._validate_operation_body(
            operation=operation,
            method=method,
            body=body,
            params=params,
        )
        return self._operation_fields(operation, method, body, params)

    def _operation_fields(
        self,
        operation: str,
        method: str,
        body: Any,
        params: dict[str, str],
    ) -> dict[str, str]:
        fields: dict[str, str] = {
            "operation": f"npm.{operation}",
        }
        package = params.get("package")
        if package:
            fields["packageName"] = unquote(package)
        for parameter, field in (
            ("revision", "revision"),
            ("tarball", "tarball"),
            ("tag", "tag"),
            ("scope", "scope"),
            ("team", "team"),
            ("token", "tokenKey"),
        ):
            value = params.get(parameter)
            if value:
                fields[field] = unquote(value)
        if operation == "distTagWrite" and method == "PUT" and isinstance(body, str):
            fields["packageVersion"] = body
        if isinstance(body, dict):
            body_package = body.get("package")
            if operation == "metadataWrite" and isinstance(body_package, str):
                fields["packageName"] = body_package
            if (
                "_rev" in body
                and (not isinstance(body["_rev"], str) or not body["_rev"])
            ):
                raise ValueError(
                    "npm_publish_revision_invalid"
                    if operation == "publish"
                    else "npm_metadata_revision_invalid"
                )
            document_name = body.get("name")
            if operation == "publish":
                if not isinstance(document_name, str) or not document_name:
                    raise ValueError("npm_publish_package_missing")
                if package and unquote(package) != document_name:
                    raise ValueError("npm_publish_package_mismatch")
                fields["packageName"] = document_name
            elif isinstance(document_name, str) and document_name:
                fields["packageName"] = document_name
            dist_tags = body.get("dist-tags")
            versions = body.get("versions")
            selected_version = (
                dist_tags.get("latest")
                if operation == "publish" and isinstance(dist_tags, dict)
                else body.get("version")
            )
            if not selected_version and isinstance(dist_tags, dict):
                selected_version = dist_tags.get("latest")
            version_doc: dict[str, Any] = {}
            if isinstance(versions, dict):
                if not selected_version and len(versions) == 1:
                    selected_version = next(iter(versions))
                candidate = versions.get(str(selected_version)) if selected_version else None
                if isinstance(candidate, dict):
                    version_doc = candidate
            if selected_version or version_doc.get("version"):
                fields["packageVersion"] = str(version_doc.get("version") or selected_version)
            if operation == "publish":
                attachments = body.get("_attachments")
                if not isinstance(attachments, dict):
                    raise ValueError("npm_publish_attachment_missing")
                if len(attachments) != 1:
                    raise ValueError("npm_publish_attachment_ambiguous")
                attachment_name, attachment = next(iter(attachments.items()))
                if not isinstance(attachment, dict):
                    raise ValueError("npm_publish_attachment_invalid")
                encoded = attachment.get("data")
                if not isinstance(encoded, str):
                    raise ValueError("npm_publish_attachment_data_missing")
                max_encoded_bytes = (_MAX_NPM_ATTACHMENT_BYTES * 4) // 3 + 4
                if len(encoded) > max_encoded_bytes:
                    raise ValueError("npm_publish_attachment_too_large")
                try:
                    tarball = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise ValueError("npm_publish_attachment_invalid_base64") from exc
                if base64.b64encode(tarball).decode("ascii") != encoded:
                    raise ValueError("npm_publish_attachment_invalid_base64")
                if len(tarball) > _MAX_NPM_ATTACHMENT_BYTES:
                    raise ValueError("npm_publish_attachment_too_large")
                if not tarball:
                    raise ValueError("npm_publish_attachment_empty")
                if "length" in attachment and (
                    not isinstance(attachment["length"], int)
                    or isinstance(attachment["length"], bool)
                    or attachment["length"] != len(tarball)
                ):
                    raise ValueError("npm_publish_attachment_length_mismatch")
                integrity = "sha512-" + base64.b64encode(
                    hashlib.sha512(tarball).digest()
                ).decode("ascii")
                declarations: list[tuple[str, Any]] = []
                if "tarball_integrity" in body:
                    declarations.append(("tarball_integrity", body["tarball_integrity"]))
                dist = version_doc.get("dist")
                if isinstance(dist, dict) and "integrity" in dist:
                    declarations.append(("versions.dist.integrity", dist["integrity"]))
                if "_integrity" in version_doc:
                    declarations.append(("versions._integrity", version_doc["_integrity"]))
                if any(
                    not isinstance(declared, str) or declared != integrity
                    for _source, declared in declarations
                ):
                    raise ValueError("npm_publish_integrity_mismatch")
                fields["tarballIntegrity"] = integrity
                fields["attachmentName"] = str(attachment_name)
                fields["attachmentBytes"] = str(len(tarball))
        return fields

    def _validate_unpublish_update(
        self,
        body: Any,
        params: dict[str, str],
    ) -> None:
        if not isinstance(body, dict):
            raise ValueError("npm_unpublish_body_required")
        revision = body.get("_rev")
        path_revision = unquote(params.get("revision") or "")
        if not isinstance(revision, str) or not revision:
            raise ValueError("npm_unpublish_revision_invalid")
        if not path_revision or revision != path_revision:
            raise ValueError("npm_unpublish_revision_mismatch")
        package = unquote(params.get("package") or "")
        document_name = body.get("name")
        if not self._valid_package_name(document_name):
            raise ValueError("npm_unpublish_package_missing")
        if package and package != document_name:
            raise ValueError("npm_unpublish_package_mismatch")
        if "_attachments" in body or "_revisions" in body:
            raise ValueError("npm_unpublish_forbidden_field")
        versions = body.get("versions")
        if not isinstance(versions, dict) or not versions:
            raise ValueError("npm_unpublish_versions_invalid")
        for version, document in versions.items():
            if (
                not self._valid_dist_tag_version(version)
                or not isinstance(document, dict)
                or document.get("version") != version
            ):
                raise ValueError("npm_unpublish_versions_invalid")
            version_name = document.get("name")
            if version_name is not None and version_name != document_name:
                raise ValueError("npm_unpublish_package_mismatch")
        dist_tags = body.get("dist-tags")
        if not isinstance(dist_tags, dict):
            raise ValueError("npm_unpublish_dist_tags_invalid")
        latest = dist_tags.get("latest")
        if not isinstance(latest, str) or latest not in versions:
            raise ValueError("npm_unpublish_dist_tags_invalid")
        if any(
            not isinstance(tag, str)
            or not tag
            or not isinstance(version, str)
            or version not in versions
            for tag, version in dist_tags.items()
        ):
            raise ValueError("npm_unpublish_dist_tags_invalid")

    def _validate_team_access_delete(
        self,
        body: Any,
        params: dict[str, str],
    ) -> None:
        if not isinstance(body, dict) or set(body) != {"package"}:
            raise ValueError("npm_team_access_delete_body_invalid")
        package = body.get("package")
        if not self._valid_package_name(package):
            raise ValueError("npm_team_access_package_invalid")
        scope = unquote(params.get("scope") or "")
        if not scope or not package.startswith(f"@{scope}/"):
            raise ValueError("npm_team_access_scope_mismatch")

    def _validate_deprecation_packument(
        self,
        body: dict[str, Any],
        params: dict[str, str],
    ) -> None:
        package = unquote(params.get("package") or "")
        document_name = body.get("name")
        if not self._valid_package_name(document_name):
            raise ValueError("npm_metadata_package_missing")
        if package and package != document_name:
            raise ValueError("npm_metadata_package_mismatch")
        if "tarball_integrity" in body:
            raise ValueError("npm_metadata_publish_payload_denied")
        attachments = body.get("_attachments")
        if attachments is not None:
            if not isinstance(attachments, dict) or any(
                not isinstance(attachment, dict) or "data" in attachment
                for attachment in attachments.values()
            ):
                raise ValueError("npm_metadata_publish_payload_denied")
        versions = body.get("versions")
        dist_tags = body.get("dist-tags")
        if not isinstance(versions, dict) or not versions or not isinstance(dist_tags, dict):
            raise ValueError("npm_metadata_packument_invalid")
        deprecation_fields = 0
        for version, document in versions.items():
            if (
                not self._valid_dist_tag_version(version)
                or not isinstance(document, dict)
                or document.get("version") != version
            ):
                raise ValueError("npm_metadata_packument_invalid")
            version_name = document.get("name")
            if version_name is not None and version_name != document_name:
                raise ValueError("npm_metadata_package_mismatch")
            if "deprecated" in document:
                deprecated = document["deprecated"]
                if (
                    not isinstance(deprecated, str)
                    or len(deprecated.encode("utf-8")) > 4096
                ):
                    raise ValueError("npm_metadata_deprecation_invalid")
                deprecation_fields += 1
        if deprecation_fields == 0:
            raise ValueError("npm_metadata_deprecation_required")
        if any(
            not isinstance(tag, str)
            or not tag
            or not isinstance(version, str)
            or version not in versions
            for tag, version in dist_tags.items()
        ):
            raise ValueError("npm_metadata_dist_tags_invalid")

    def _validate_operation_body(
        self,
        *,
        operation: str,
        method: str,
        body: Any,
        params: dict[str, str],
    ) -> None:
        if operation == "tokenCreate":
            raise ValueError("npm_token_creation_denied")
        if operation == "distTagWrite":
            if method == "PUT":
                if not self._valid_dist_tag_version(body):
                    raise ValueError("npm_dist_tag_version_invalid")
            elif body is not None:
                raise ValueError("npm_delete_body_denied")
            return
        if operation == "unpublish":
            if method == "PUT":
                self._validate_unpublish_update(body, params)
            elif body is not None:
                raise ValueError("npm_delete_body_denied")
            return
        if operation == "metadataWrite" and method == "DELETE":
            self._validate_team_access_delete(body, params)
            return
        if method in {"PUT", "POST"} and not isinstance(body, dict):
            raise ValueError("npm_write_body_required")
        if method == "DELETE" and body is not None:
            raise ValueError("npm_delete_body_denied")
        if (
            operation == "metadataWrite"
            and isinstance(body, dict)
            and "_rev" in body
            and (not isinstance(body["_rev"], str) or not body["_rev"])
        ):
            raise ValueError("npm_metadata_revision_invalid")
        if (
            operation == "metadataWrite"
            and method == "PUT"
            and isinstance(body, dict)
            and any(field in body for field in ("versions", "dist-tags", "_attachments"))
        ):
            self._validate_deprecation_packument(body, params)

    def _validate_publish_document(
        self,
        body: dict[str, Any] | None,
        params: dict[str, str],
    ) -> PolicyDecision:
        if not isinstance(body, dict):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish body must be a JSON object",
                payload={"error": "npm_publish_invalid_json"},
            )
        if "_rev" in body and (
            not isinstance(body["_rev"], str) or not body["_rev"]
        ):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish revision must be a nonempty string when present",
                payload={"error": "npm_publish_revision_invalid"},
            )
        route_package = unquote(params.get("package") or "")
        document_package = body.get("name")
        if not isinstance(document_package, str) or not document_package:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish body must declare the package name",
                payload={"error": "npm_publish_package_missing"},
            )
        if route_package and route_package != document_package:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish package does not match the authorized route",
                payload={
                    "error": "npm_publish_package_mismatch",
                    "route_package": route_package,
                    "document_package": document_package,
                },
            )
        versions = body.get("versions")
        if not isinstance(versions, dict) or len(versions) != 1:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish must contain exactly one package version",
                payload={
                    "error": "npm_publish_requires_exactly_one_version",
                    "version_count": len(versions) if isinstance(versions, dict) else 0,
                },
            )
        version, version_document = next(iter(versions.items()))
        latest = (body.get("dist-tags") or {}).get("latest") if isinstance(body.get("dist-tags"), dict) else None
        if latest != version:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish latest tag must reference the sole authorized version",
                payload={"error": "npm_publish_latest_tag_mismatch", "latest": latest, "version": version},
            )
        if not isinstance(version_document, dict) or version_document.get("version") != version:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm publish version document does not match its version key",
                payload={"error": "npm_publish_version_mismatch", "version": version},
            )
        return PolicyDecision(allowed=True)

    def validate_request(self, flow: Any, route: Any, params: dict[str, str]) -> PolicyDecision:
        profile_decision = self._validate_provider_request_profile(flow, route)
        if not profile_decision.allowed:
            return profile_decision
        method = flow.request.method.upper()
        try:
            body = self._json_body(flow) if method not in {"GET", "HEAD"} else None
        except (UnicodeError, ValueError, RecursionError):
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm write body must be strict JSON",
                payload={"error": "npm_write_invalid_json"},
            )
        try:
            operation = self._operation_name(flow, params, body)
        except ValueError:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm request does not match a configured write operation",
                payload={"error": "npm_operation_unclassified"},
            )
        try:
            self._validate_operation_body(
                operation=operation,
                method=method,
                body=body,
                params=params,
            )
        except ValueError as exc:
            error = str(exc)
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason="npm request body does not match the closed operation grammar",
                payload={"error": error},
            )
        allowed_operations = set(route.adapter_config.get("operations") or [])
        if operation not in allowed_operations:
            return PolicyDecision(
                allowed=False,
                status_code=403,
                reason=f"npm operation {operation} is not allowed by route policy",
                payload={"error": "npm_operation_not_allowed", "operation": operation},
            )
        if operation == "publish":
            document_decision = self._validate_publish_document(body, params)
            if not document_decision.allowed:
                return document_decision
            try:
                fields = self._operation_fields(operation, method, body, params)
            except ValueError as exc:
                error = str(exc)
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason="npm publish attachment integrity could not be verified",
                    payload={"error": error},
                )
            missing = [
                field
                for field in ("packageName", "packageVersion", "tarballIntegrity")
                if not fields.get(field)
            ]
            if missing:
                return PolicyDecision(
                    allowed=False,
                    status_code=403,
                    reason=f"npm publish request missing required operation fields: {', '.join(missing)}",
                    payload={"error": "npm_publish_missing_fields", "missing": missing},
                )
        return PolicyDecision(allowed=True)


ADAPTERS: dict[str, ApiAdapter] = {
    "generic.rest": ApiAdapter(),
    "gmail.v1": GmailV1Adapter(),
    "x.v2": XV2Adapter(),
    "npm.registry": NpmRegistryAdapter(),
}


def get_adapter(adapter_type: str) -> ApiAdapter:
    if adapter_type not in ADAPTERS:
        raise KeyError(f"unsupported adapter: {adapter_type}")
    return ADAPTERS[adapter_type]
